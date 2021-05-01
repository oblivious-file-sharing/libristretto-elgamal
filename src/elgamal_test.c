#include <ristretto_elgamal.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>

/*
* This executable program loads the key and the map and performs some basic checks.
*/

int main() {
	ristretto255_scalar_t sk_1[59];
	ristretto255_scalar_t sk_2[59];

	ristretto255_point_t pk_1[59];
	ristretto255_point_t pk_2[59];
	ristretto255_point_t pk[59];

	printf("\033[0;32m[INFO]\033[0m Loading the two key pairs and the merged public key...\n");

	LoadPrivKey(sk_1, "./priv_1.key");
	LoadPrivKey(sk_2, "./priv_2.key");

	LoadPubKey(pk_1, "./pub_1.key");
	LoadPubKey(pk_2, "./pub_2.key");
	LoadPubKey(pk, "./pub.key");

	printf("\033[0;32m[INFO]\033[0m The key pairs have been loaded.\n");

	fastecexp_state st_pk1[60];
	fastecexp_state st_pk2[60];
	fastecexp_state st_pk[60];

	char filename[59][150];

	printf("\033[0;32m[INFO]\033[0m Loading the precomputation tables for PK1...\n");
#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], "/table/pub_1_%d.tab", i);
		TableLoad(&st_pk1[i], filename[i]);
	}
	printf("\033[0;32m[INFO]\033[0m PK1's precomputation tables have been loaded.\n");
	TableLoad(&st_pk1[59], "/table/pub_1_59.tab");

	printf("\033[0;32m[INFO]\033[0m Loading the precomputation tables for PK2...\n");
#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], "/table/pub_2_%d.tab", i);
		TableLoad(&st_pk2[i], filename[i]);
	}
	printf("\033[0;32m[INFO]\033[0m PK2's precomputation tables have been loaded.\n");
	TableLoad(&st_pk2[59], "/table/pub_2_59.tab");
	
	printf("\033[0;32m[INFO]\033[0m Loading the precomputation tables for PK...\n");
#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], "/table/pub_%d.tab", i);
		TableLoad(&st_pk[i], filename[i]);
	}
	printf("\033[0;32m[INFO]\033[0m PK's precomputation tables have been loaded.\n");
	TableLoad(&st_pk[59], "/table/pub_59.tab");

	int BLOCK = 36;
	ristretto255_point_t output[59 * BLOCK];
	uint8_t input[1827 * BLOCK];
	uint8_t recovered[1827 * BLOCK];
	size_t actual_size;

	FILE *rand_src = fopen("/dev/urandom", "rb");
	fread(input, 1827 * BLOCK - 1, 1, rand_src);
	fclose(rand_src);

	struct timespec t_start, t_end;

	printf("\033[0;32m[INFO]\033[0m Testing encoding + decoding, without encryption or decryption.\n");

	ristretto_elgamal_encode(output, input, 1827 * BLOCK - 1, 1827 * BLOCK); // warmup
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int i = 0; i < 10; i++)
		ristretto_elgamal_encode(output, input, 1827 * BLOCK - 1, 1827 * BLOCK);
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Encoding time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	memset(recovered, 0, 1827 * BLOCK);
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int i = 0; i < 10; i++)
		ristretto_elgamal_decode(recovered, output, 59 * BLOCK, &actual_size, 1827 * BLOCK);
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Decoding time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	for (int i = 0; i < 1827 * BLOCK - 1; i++) {
		if (recovered[i] != input[i]) {
			printf("\033[0;31m[ERROR]\033[0m recovered[%d] = %d, should be %d, point of problem: %d\n", i, recovered[i],
				   input[i], (i + 31) / 32);
		}
	}
	printf("\033[0;32m[INFO]\033[0m Recovered actual_size = %ld\n", actual_size);

	printf("\033[0;32m[INFO]\033[0m Testing encoding + encryption + decryption + decoding, without rerandomization, focusing on key 1.\n");
	ristretto255_point_t ct[60 * BLOCK];
	ristretto255_point_t recovered_output[59 * BLOCK];
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
#pragma omp parallel for
		for (int i = 0; i < BLOCK; i++) {
			Encrypt(&ct[i * 60], &output[i * 59], st_pk1, rand_src);
		}
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Encryption time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	ristretto255_point_t ct_rand[60 * BLOCK];
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
#pragma omp parallel for
		for (int i = 0; i < BLOCK; i++) {
			Rerand_to_cache(&ct_rand[i * 60], st_pk1, rand_src);
		}
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Rerand, offline time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
#pragma omp parallel for
		for (int i = 0; i < BLOCK; i++) {
			Rerand_use_cache(&ct[i * 60], &ct_rand[i * 60]);
		}
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Rerand, online time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
#pragma omp parallel for
		for (int i = 0; i < BLOCK; i++) {
			Decrypt(&recovered_output[i * 59], &ct[i * 60], sk_1);
		}
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Decryption time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);
	memset(recovered, 0, 1827 * BLOCK);
	ristretto_elgamal_decode(recovered, recovered_output, 59 * BLOCK, &actual_size, 1827 * BLOCK);
	for (int i = 0; i < 1827 * BLOCK - 1; i++) {
		if (recovered[i] != input[i]) {
			printf("\033[0;31m[ERROR]\033[0m recovered[%d] = %d, should be %d, point of problem: %d.\n", i,
				   recovered[i], input[i], (i + 31) / 32);
			break;
		}
	}
	printf("\033[0;32m[INFO]\033[0m Recovered actual_size = %ld.\n", actual_size);

	printf("\033[0;32m[INFO]\033[0m Testing encoding + encryption +rerandomization + decryption + decoding, focusing on key 1.\n");
	ristretto255_point_t ct_rerand[60 * BLOCK];
#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		Encrypt(&ct[i * 60], &output[i * 59], st_pk1, rand_src);
	}
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
#pragma omp parallel for
		for (int i = 0; i < BLOCK; i++) {
			Rerand(&ct_rerand[i * 60], &ct[i * 60], st_pk1, rand_src);
		}
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Rerandomization time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);
#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		Decrypt(&recovered_output[i * 59], &ct_rerand[i * 60], sk_1);
	}
	memset(recovered, 0, 1827 * BLOCK);
	ristretto_elgamal_decode(recovered, recovered_output, 59 * BLOCK, &actual_size, 1827 * BLOCK);
	for (int i = 0; i < 1827 * BLOCK - 1; i++) {
		if (recovered[i] != input[i]) {
			printf("\033[0;31m[ERROR]\033[0m recovered[%d] = %d, should be %d, point of problem: %d.\n", i,
				   recovered[i], input[i], (i + 31) / 32);
		}
	}
	printf("\033[0;32m[INFO]\033[0m Recovered actual_size = %ld.\n", actual_size);

	printf("\033[0;32m[INFO]\033[0m Testing encoding + encryption +rerandomization + decryption + decoding, with distributed decryption.\n");
#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		Encrypt(&ct[i * 60], &output[i * 59], st_pk, rand_src);
	}

	/*
	* serialize it!
	*/
	unsigned char *str = malloc(sizeof(char) * Serialize_Malicious_Size(60 * BLOCK));
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
		Serialize_Malicious(str, ct, 60 * BLOCK);
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Serialization -- malicious time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	/*
	* then recover it back.
	*/
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
		Deserialize_Malicious(ct, str, 60 * BLOCK);
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Deserialization -- malicious time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		Rerand(&ct_rerand[i * 60], &ct[i * 60], st_pk, rand_src);
	}

	/*
	* serialize it!
	*/
	unsigned char *str2 = malloc(sizeof(char) * Serialize_Honest_Size(60 * BLOCK));
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
		Serialize_Honest(str2, ct_rerand, 60 * BLOCK);
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Serialization -- honest time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

	/*
	* then recover it back.
	*/
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 10; pp++) {
		Deserialize_Honest(ct_rerand, str2, 60 * BLOCK);
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Deserialization -- honest time: %lf.\n",
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) * 1.0 / 1000000000);

#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		Rerand(&ct[i * 60], &ct_rerand[i * 60], st_pk, rand_src);
	}
#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		Decrypt(&recovered_output[i * 59], &ct[i * 60], sk_2);
	}
	ristretto255_point_t recovered_output2[59 * BLOCK];
	ristretto255_point_t distributed_decryption_ct[BLOCK][1];
	for (int i = 0; i < BLOCK; i++) {
		PartDec1(distributed_decryption_ct[i], &ct[i * 60]);
	}
#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		PartDec2(&recovered_output2[i * 59], distributed_decryption_ct[i], sk_1);
	}
#pragma omp parallel for
	for (int i = 0; i < BLOCK; i++) {
		PartDec3(&recovered_output2[i * 59], &recovered_output[i * 59]);
	}

	memset(recovered, 0, 1827 * BLOCK);
	ristretto_elgamal_decode(recovered, recovered_output2, 59 * BLOCK, &actual_size, 1827 * BLOCK);
	for (int i = 0; i < 1827 * BLOCK - 1; i++) {
		if (recovered[i] != input[i]) {
			printf("\033[0;32m[INFO]\033[0m recovered[%d] = %d, should be %d, point of problem: %d.\n", i, recovered[i],
				   input[i], (i + 31) / 32);
			break;
		}
	}
	printf("\033[0;32m[INFO]\033[0m Recovered actual_size = %ld.\n", actual_size);

	fclose(rand_src);

	for (int i = 0; i < 59; i++) {
		TableRelease(&st_pk1[i]);
		TableRelease(&st_pk2[i]);
		TableRelease(&st_pk[i]);
	}

	free(str);
	free(str2);
	return 0;
}
