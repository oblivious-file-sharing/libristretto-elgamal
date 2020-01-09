#include <ristretto_elgamal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
* This executable file tries to embed a string without using a hint. This approach relies on a hash function to decide the unique preimage.
*/

int main() {
	point_t test;
	uint8_t ser[SER_BYTES];
	memset(ser, 0, SER_BYTES);

	srand(time(0));
	/* first 21 bytes are okay */
	for (int i = 0; i < 21; i++) {
		ser[i] = rand() % 255;
	}
	/* the 22nd byte we only have 6 bits */
	ser[21] = rand() & 63;

	printf("\033[0;32m[INFO]\033[0m Embedding 174 bits, as follows.\n");
	ristretto_elgamal_char_printf("str1", ser);

	uint8_t ser2[SER_BYTES];
	memset(ser2, 0, SER_BYTES);

	ristretto_elgamal_encode_single_message_hintless_hashonly(&test, ser);
	ristretto_elgamal_decode_single_message_hintless_hashonly(&test, ser2);

	printf("\033[0;32m[INFO]\033[0m Extracted 174 bits after the hintless encoding, as follows.\n");
	ristretto_elgamal_char_printf("str2", ser2);

	return 0;
}
