#include <ristretto_elgamal.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>

/*
* This executable program creates dummy ciphertexts under a specific pair of public keys
* In order to create the dummy ciphertext for 574-block case,
*    the stack size limit may need to be elevated.
*/

int main() {
	printf("\033[0;32m[INFO]\033[0m Loading public keys from the current directory...\n");

	ristretto255_point_t pk[59];
	LoadPubKey(pk, "./pub.key");

	fastecexp_state st_pk[60];
	char filename[59][150];

#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], "/table/pub_%d.tab", i);
		TableLoad(&st_pk[i], filename[i]);
	}
	TableLoad(&st_pk[59], "/table/pub_base.tab");
	printf("\033[0;32m[INFO]\033[0m Public keys loaded.\n");

	int BLOCK_array[4];
	BLOCK_array[0] = 3;
	BLOCK_array[1] = 9;
	BLOCK_array[2] = 36;
	BLOCK_array[3] = 574;
	/* 1MB => 574, 64KB => 36, 16KB => 9, 4KB => 3 */

	for (int BLOCK_array_index = 0; BLOCK_array_index < 4; BLOCK_array_index++) {
		int BLOCK = BLOCK_array[BLOCK_array_index];

		printf("\033[0;32m[INFO]\033[0m Preparing a dummy ciphertext of %d blocks.\n", BLOCK);

		uint8_t input[1827 * BLOCK];
		memset(input, 0, sizeof(input));

		FILE *rand_src = fopen("/dev/urandom", "rb");

		/* encode */
		ristretto255_point_t output[59 * BLOCK];
		ristretto_elgamal_encode(output, input, 0, 1827 * BLOCK);

		/* encrypt */
		ristretto255_point_t ct[60 * BLOCK];
		for (int i = 0; i < BLOCK; i++) {
			Encrypt(&ct[i * 60], &output[i * 59], st_pk, rand_src);
		}
		fclose(rand_src);

		/* encode the ciphertext */
		size_t serialized_ct_size = Serialize_Honest_Size(60 * BLOCK);
		unsigned char *str = malloc(sizeof(char) * serialized_ct_size);
		Serialize_Honest(str, ct, 60 * BLOCK);

		/* encode the plaintext */
		size_t serialized_pt_size = Serialize_Honest_Size(59 * BLOCK);
		unsigned char *str_pt = malloc(sizeof(char) * serialized_pt_size);
		Serialize_Honest(str_pt, output, 59 * BLOCK);
		Deserialize_Honest(output, str_pt, 59 * BLOCK);

		printf("\033[0;32m[INFO]\033[0m Writing the dummy ciphertext of %d blocks to ./data/dummy_ciphertext_%d.\n",
			   BLOCK, BLOCK);

		char filename_dummy_ciphertext[150];
		sprintf(filename_dummy_ciphertext, "./data/dummy_ciphertext_%d", BLOCK);

		FILE *fp_dummy_ciphertext = fopen(filename_dummy_ciphertext, "wb");
		if (fp_dummy_ciphertext == NULL) {
			printf("\033[0;31m[ERROR]\033[0m Failed to write the dummy ciphertext.\n");
			exit(1);
		}
		fwrite(str, serialized_ct_size, 1, fp_dummy_ciphertext);
		fclose(fp_dummy_ciphertext);

		printf("\033[0;32m[INFO]\033[0m Dummy ciphertext of %d blocks written.\n", BLOCK);

		printf("\033[0;32m[INFO]\033[0m Writing the dummy plaintext of %d blocks to ./data/dummy_plaintext_%d.\n",
			   BLOCK, BLOCK);

		char filename_dummy_plaintext[150];
		sprintf(filename_dummy_plaintext, "./data/dummy_plaintext_%d", BLOCK);

		FILE *fp_dummy_plaintext = fopen(filename_dummy_plaintext, "wb");
		if (fp_dummy_plaintext == NULL) {
			printf("\033[0;31m[ERROR]\033[0m Failed to write the dummy plaintext.\n");
			exit(1);
		}
		fwrite(str_pt, serialized_pt_size, 1, fp_dummy_plaintext);
		fclose(fp_dummy_plaintext);

		printf("\033[0;32m[INFO]\033[0m Dummy plaintext of %d blocks written.\n", BLOCK);

		printf("\033[0;32m[INFO]\033\033\033[0m Checking if the dummy ciphertext can be decrypted correctly...\n");
		uint8_t recovered[1827 * BLOCK];
		size_t actual_size;
		memset(input, 0, sizeof(input));
		ristretto_elgamal_decode(recovered, output, 59 * BLOCK, &actual_size, 1827 * BLOCK);
		printf("\033[0;32m[INFO]\033\033[0m Decrypted plaintext has a size of %ld bytes (expected: 0 bytes).\n",
			   actual_size);

		free(str);
	}

	for (int i = 0; i < 59; i++) {
		TableRelease(&st_pk[i]);
	}

	return 0;
}
