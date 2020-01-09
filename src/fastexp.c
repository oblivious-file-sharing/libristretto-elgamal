#include <ristretto_elgamal.h>
#include "word.h"
#include "field.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include <xmmintrin.h>

/*
* We use 16 for the server side; the client side can leverage a window of size 8.
*/
int ADJUST_WINDOW = 16;

void AdjustWindow(const int new_window_size){
	ADJUST_WINDOW = new_window_size;
}

void TableGen(const ristretto255_point_t *base, const char *filename) {
	fastecexp_state st;
	fastecexp_prepare(base, 255, ADJUST_WINDOW, &st);
	fastecexp_export_table(&st, filename);
	fastecexp_release(&st);
}

void TableLoad(fastecexp_state *pst, const char *filename) {
	fastecexp_prepare_with_import_table(255, ADJUST_WINDOW, pst, filename);
}

void TableRelease(fastecexp_state *pst) {
	fastecexp_release(pst);
}

void TableCompute(const fastecexp_state *pst, ristretto255_point_t *p, unsigned char *exp) {
	fastecexp_compute(p, exp, pst);
}

void
fastecexp_prepare(const ristretto255_point_t *base, const int exp_len, const int group_slice_len, fastecexp_state *st) {
	int num_group;
	num_group = (exp_len + group_slice_len - 1) / group_slice_len;

	int group_size;
	group_size = 1 << group_slice_len;

	st->exp_len = exp_len;
	st->group_slice_len = group_slice_len;
	st->num_group = num_group;
	st->group_size = group_size;
	st->precompute_table = (ristretto255_point_t *) malloc(sizeof(ristretto255_point_t) * num_group * group_size);

	if (st->precompute_table == NULL) {
		printf("\033[0;31m[ERROR]\033[0m Memory allocation for the precomputation table failed.\n");
		exit(1);
	}

	ristretto255_point_t cur;
	ristretto255_point_t cur_add;
	ristretto255_point_copy(&cur, &ristretto255_point_identity);
	ristretto255_point_copy(&cur_add, base);

	int counter = 0;
	for (int i = 0; i < num_group; i++) {
		for (int j = 0; j < group_size; j++) {
			ristretto255_point_copy(&st->precompute_table[counter], &cur);

			ristretto255_point_add(&cur, &cur, &cur_add);
			counter++;
		}
		ristretto255_point_copy(&cur_add, &cur);
		ristretto255_point_copy(&cur, base);
	}
}

void fastecexp_export_table(const fastecexp_state *st, const char *filename) {
	FILE *fp = fopen(filename, "wb");

	char buffer[65536];
	setvbuf(fp, buffer, _IOFBF, 65536);
	if (fp == NULL) {
		printf("\033[0;31m[ERROR]\033[0m Cannot open a file to export the fastecexp table.\n");
		exit(1);
	}

	for (int i = 0; i < st->num_group; i++) {
		for (int j = 0; j < st->group_size; j++) {
			fwrite(&st->precompute_table[i * (st->group_size) + j], sizeof(ristretto255_point_t), 1, fp);
		}
	}

	fclose(fp);
}


void fastecexp_prepare_with_import_table(const int exp_len, const int group_slice_len, fastecexp_state *st,
										 const char *filename) {
	int num_group;
	num_group = (exp_len + group_slice_len - 1) / group_slice_len;

	int group_size;
	group_size = 1 << group_slice_len;

	st->exp_len = exp_len;
	st->group_slice_len = group_slice_len;
	st->num_group = num_group;
	st->group_size = group_size;
	st->precompute_table = (ristretto255_point_t *) malloc(sizeof(ristretto255_point_t) * num_group * group_size);

	if (st->precompute_table == NULL) {
		printf("\033[0;31m[ERROR]\033[0m Memory allocation for the precomputation table failed.\n");
		exit(1);
	}

	FILE *fp = fopen(filename, "rb");
	char buffer[65536];
	setvbuf(fp, buffer, _IOFBF, 65536);

	if (fp == NULL) {
		printf("\033[0;31m[ERROR]\033[0m Cannot open a file to import the precomputation table.\n");
		exit(1);
	}

	for (int i = 0; i < st->num_group; i++) {
		for (int j = 0; j < st->group_size; j++) {
			fread(&st->precompute_table[i * (st->group_size) + j], sizeof(ristretto255_point_t), 1, fp);
		}
	}

	fclose(fp);
}

void fastecexp_compute(ristretto255_point_t *result, const unsigned char *exp, const fastecexp_state *st) {
	unsigned char *expanded_exp = (unsigned char *) malloc(sizeof(unsigned char) * 300);
	memset(expanded_exp, 0, 300);
	for (int i = 0; i < (st->exp_len + 8 - 1) / 8; i++) {
		expanded_exp[i * 8 + 7] = (exp[i] >> 7) & 1;
		expanded_exp[i * 8 + 6] = (exp[i] >> 6) & 1;
		expanded_exp[i * 8 + 5] = (exp[i] >> 5) & 1;
		expanded_exp[i * 8 + 4] = (exp[i] >> 4) & 1;
		expanded_exp[i * 8 + 3] = (exp[i] >> 3) & 1;
		expanded_exp[i * 8 + 2] = (exp[i] >> 2) & 1;
		expanded_exp[i * 8 + 1] = (exp[i] >> 1) & 1;
		expanded_exp[i * 8 + 0] = exp[i] & 1;
	}

	int counter = 0;
	int step;

	ristretto255_point_copy(result, &ristretto255_point_identity);

	for (int i = 0; i < st->num_group; i++) {
		step = expanded_exp[counter];
		counter++;
		for (int j = 1; j < st->group_slice_len; j++) {
			step = step + (expanded_exp[counter] << j);
			counter++;
		}

		ristretto255_point_t *added_point_addr;
		added_point_addr = &st->precompute_table[(i * st->group_size) + step];

		ristretto255_point_add(result, result, added_point_addr);

		char *added_point_addr_char = (char *) added_point_addr;

		// assume that the cache line is 64byte and the size of the point is 320bit*4=1280bit=160byte
		_mm_clflush(&added_point_addr_char[0]);
		_mm_clflush(&added_point_addr_char[64]);
		_mm_clflush(&added_point_addr_char[128]);
	}

	free(expanded_exp);
}

void fastecexp_release(fastecexp_state *st) {
	free(st->precompute_table);
	st->precompute_table = NULL;

	st->exp_len = 0;
	st->group_slice_len = 0;
	st->num_group = 0;
	st->group_size = 0;
}
