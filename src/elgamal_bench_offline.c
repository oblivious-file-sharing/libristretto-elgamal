#include <ristretto_elgamal.h>
#include <omp.h>
#include <time.h>
#include <stdio.h>

/*
* This executable program loads the key and the map and precomputes g^r
*/

void bench(int BLOCK, fastecexp_state *st_pk1) {
	ristretto255_point_t output[59 * BLOCK];
	uint8_t input[1827 * BLOCK];
	uint8_t recovered[1827 * BLOCK];
	size_t actual_size;

	FILE *rand_src = fopen("/dev/urandom", "rb");
	fread(input, 1827 * BLOCK - 1, 1, rand_src);
	fclose(rand_src);

	struct timespec t_start, t_end;

	ristretto_elgamal_encode(output, input, 1827 * BLOCK - 1, 1827 * BLOCK);

	ristretto255_point_t ct_rand[60 * BLOCK];
	clock_gettime(CLOCK_REALTIME, &t_start);
	for (int pp = 0; pp < 1000; pp++) {
#pragma omp parallel for
		for (int i = 0; i < BLOCK; i++) {
			Rerand_to_cache(&ct_rand[i * 60], st_pk1, rand_src);
		}
	}
	clock_gettime(CLOCK_REALTIME, &t_end);
	printf("\033[0;32m[INFO]\033[0m Rerand 1000 ciphertexts of %d blocks, offline time: %lf seconds.\n", BLOCK,
		   t_end.tv_sec - t_start.tv_sec + (t_end.tv_nsec - t_start.tv_nsec) / 1000000000.);
}

int main() {
	fastecexp_state st_pk1[60];

	char filename[59][150];
	printf("\033[0;32m[INFO]\033[0m Loading the precomputation tables for PK1...\n");
#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], "/table/pub_1_%d.tab", i);
		TableLoad(&st_pk1[i], filename[i]);
	}
	printf("\033[0;32m[INFO]\033[0m PK1's precomputation tables have been loaded.\n");
	TableLoad(&st_pk1[59], "/table/pub_1_base.tab");

	bench(36, st_pk1);
	bench(9, st_pk1);
	bench(3, st_pk1);

	for (int i = 0; i < 59; i++) {
		TableRelease(&st_pk1[i]);
	}
	return 0;
}
