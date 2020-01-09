#include <ristretto_elgamal.h>
#include <stdio.h>
#include <time.h>

/*
* This executable file is for internal testing about moving bits.
*/

int main() {
	uint8_t ser[SER_BYTES];

	srand(time(0));
	for (int i = 0; i < SER_BYTES; i++) {
		ser[i] = rand() % 255;
	}

	printf("\033[0;32m[INFO]\033[0m The first test tries to move forward the string by 5 bits.\n");

	printf("Original: \n");
	for (int i = 0; i < SER_BYTES; i++) {
		for (int j = 0; j < 8; j++) {
			printf("%d ", (ser[i] >> j) & 1);
		}
		printf("\n");
	}
	printf("\n");

	uint8_t ser2[SER_BYTES];
	shift_to_higher_index(5, ser2, ser, SER_BYTES);

	printf("Result: \n");
	for (int i = 0; i < SER_BYTES; i++) {
		for (int j = 0; j < 8; j++) {
			printf("%d ", (ser2[i] >> j) & 1);
		}
		printf("\n");
	}
	printf("\n");

	printf("=========================================\n\n");

	printf("\033[0;32m[INFO]\033[0m The second test tries to move backward the string by 5 bits.\n");

	printf("Original: \n");
	for (int i = 0; i < SER_BYTES; i++) {
		for (int j = 0; j < 8; j++) {
			printf("%d ", (ser[i] >> j) & 1);
		}
		printf("\n");
	}
	printf("\n");

	uint8_t ser3[SER_BYTES];
	shift_to_lower_index(5, ser3, ser, SER_BYTES);

	printf("Result: \n");
	for (int i = 0; i < SER_BYTES; i++) {
		for (int j = 0; j < 8; j++) {
			printf("%d ", (ser3[i] >> j) & 1);
		}
		printf("\n");
	}
	printf("\n");
}
