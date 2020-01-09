#include <ristretto_elgamal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
* This executable file tries to encode a file. This test is meaningful because it tests both encoding subsystems.
*/

int main() {
	printf("\033[0;32m[INFO]\033[0m Starting with a test for a single point...\n");
	point_t single_point_test;
	uint8_t ser[SER_BYTES];
	memset(ser, 0, SER_BYTES);

	srand(time(0));
	for (int i = 0; i < SER_BYTES; i++) {
		ser[i] = rand() % 255;
	}

	ser[0] = ser[0] & (255 - 1 - 2 - 4);
	ser[SER_BYTES - 1] = ser[SER_BYTES - 1] & 127;

	ristretto_elgamal_char_printf("  Try to embed", ser);

	mask_t sgn_ed_T, sgn_altx, sgn_s;
	ristretto_elgamal_encode_single_message(&single_point_test, ser, &sgn_ed_T, &sgn_altx, &sgn_s);
	uint8_t ser_recovered[SER_BYTES];
	memset(ser_recovered, 0, SER_BYTES);
	ristretto_elgamal_decode_single_message(&single_point_test, ser_recovered, sgn_ed_T, sgn_altx, sgn_s);

	ristretto_elgamal_char_printf("  Recovered", ser_recovered);

	printf("\n");

	printf("\033[0;32m[INFO]\033[0m Starting with a test for a ~64KB file...\n");

	int BLOCK = 36;

	point_t output[59 * BLOCK];
	uint8_t input[1827 * BLOCK];

	for (int i = 0; i < 1827 * BLOCK - 1; i++) {
		input[i] = rand() % 255;
	}

	ristretto_elgamal_encode(output, input, 1827 * BLOCK - 1, 1827 * BLOCK);

	uint8_t recovered[1827 * BLOCK];
	memset(recovered, 0, 1827 * BLOCK);
	size_t actual_size;

	ristretto_elgamal_decode(recovered, output, 59 * BLOCK, &actual_size, 1827 * BLOCK);

	for (int i = 0; i < 1827 * BLOCK - 1; i++) {
		if (recovered[i] != input[i]) {
			printf("\033[0;31m[ERROR]\033[0m recovered[%d] = %d, should be %d, point of problem: %d\n", i, recovered[i],
				   input[i], (i + 31) / 32);
		}
	}

	/* it is not 1827 * 36 = 65772 because we use one byte to label the end of the actual file, which enables us to obtain the file size. */
	printf("\033[0;32m[INFO]\033[0m Decoded plaintext's size is %ld (expect 65771 bytes).\n", actual_size);

	return 0;
}
