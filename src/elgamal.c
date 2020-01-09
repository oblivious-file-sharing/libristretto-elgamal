#include <ristretto_elgamal.h>
#include "word.h"
#include "field.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

static void gf_invert_here(gf_25519_t *y, const gf_25519_t *x, int assert_nonzero) {
	gf_25519_t t1, t2;
	gf_sqr(&t1, x); // o^2
	mask_t ret = gf_isr(&t2, &t1); // +-1/sqrt(o^2) = +-1/o
	(void) ret;
	(void) (assert_nonzero);
	//  if (assert_nonzero) assert(ret);
	gf_sqr(&t1, &t2);
	gf_mul(&t2, &t1, x); // not direct to y in case of alias.
	gf_copy(y, &t2);
}

static void gf_batch_invert_here(
		gf_25519_t *__restrict__ out,
		const gf_25519_t *in,
		unsigned int n
) {
	gf_25519_t t1;
	assert(n > 1);

	gf_copy(&out[1], &in[0]);
	int i;
	for (i = 1; i < (int) (n - 1); i++) {
		gf_mul(&out[i + 1], &out[i], &in[i]);
	}
	gf_mul(&out[0], &out[n - 1], &in[n - 1]);

	gf_invert_here(&out[0], &out[0], 1);

	for (i = n - 1; i > 0; i--) {
		gf_mul(&t1, &out[i], &out[0]);
		gf_copy(&out[i], &t1);
		gf_mul(&t1, &out[0], &in[i]);
		gf_copy(&out[0], &t1);
	}
}

void KeyGen(
		const char *filename_priv_1_key,
		const char *filename_priv_2_key,
		const char *filename_pub_1_key,
		const char *filename_pub_2_key,
		const char *filename_pub_key
) {
	FILE *fp_priv_1_key = fopen(filename_priv_1_key, "wb");
	FILE *fp_priv_2_key = fopen(filename_priv_2_key, "wb");
	FILE *fp_pub_1_key = fopen(filename_pub_1_key, "wb");
	FILE *fp_pub_2_key = fopen(filename_pub_2_key, "wb");
	FILE *fp_pub_key = fopen(filename_pub_key, "wb");

	if (fp_priv_1_key == NULL || fp_priv_2_key == NULL) {
		perror("Cannot open the file for storing the private keys.\n");
		exit(1);
	}
	if (fp_pub_1_key == NULL || fp_pub_2_key == NULL || fp_pub_key == NULL) {
		perror("Cannot open the file for storing the public keys.\n");
		exit(1);
	}

	/*
	* Step 1: Generate random values, which are going to be the private key.
	*/
	ristretto255_point_t base;
	ristretto255_point_copy(&base, &ristretto255_point_base);

	unsigned char rand255_1[59][32];
	unsigned char rand255_2[59][32];

	FILE *rand_src = fopen("/dev/urandom", "rb");
	if (rand_src == NULL) {
		perror("cannot open the random source.\n");
		exit(1);
	}

	for (int i = 0; i < 59; i++) {
		fread(rand255_1[i], 32, 1, rand_src);
	}

	for (int i = 0; i < 59; i++) {
		fread(rand255_2[i], 32, 1, rand_src);
	}

	ristretto255_scalar_t srv_1_sk[59];
	ristretto255_scalar_t srv_2_sk[59];
	ristretto255_point_t srv_1_pk[59];
	ristretto255_point_t srv_2_pk[59];
	ristretto255_point_t srv_pk[59];

	ristretto255_point_add(&base, &base, &base); // 2
	ristretto255_point_add(&base, &base, &base); // 4
	ristretto255_point_add(&base, &base, &base); // 8

	for (int i = 0; i < 59; i++) {
		fread(rand255_1, sizeof(rand255_1), 1, rand_src);
		fread(rand255_2, sizeof(rand255_2), 1, rand_src);

		ristretto255_scalar_decode_long(&srv_1_sk[i], rand255_1[i], 32);
		ristretto255_scalar_decode_long(&srv_2_sk[i], rand255_2[i], 32);

		ristretto255_point_scalarmul(&srv_1_pk[i], &base, &srv_1_sk[i]);
		ristretto255_point_scalarmul(&srv_2_pk[i], &base, &srv_2_sk[i]);

		ristretto255_point_add(&srv_pk[i], &srv_1_pk[i], &srv_2_pk[i]);
	}

	for (int i = 0; i < 59; i++) {
		fwrite(&srv_1_sk[i], sizeof(ristretto255_scalar_t), 1, fp_priv_1_key);
		fwrite(&srv_2_sk[i], sizeof(ristretto255_scalar_t), 1, fp_priv_2_key);

		fwrite(&srv_1_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_1_key);
		fwrite(&srv_2_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_2_key);

		fwrite(&srv_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_key);
	}

	fclose(fp_priv_1_key);
	fclose(fp_priv_2_key);
	fclose(fp_pub_1_key);
	fclose(fp_pub_2_key);
	fclose(fp_pub_key);

	fclose(rand_src);
}

void KeyGen_stage1(
		const char *filename_priv_srv_key,
		const char *filename_pub_srv_key
) {
	FILE *fp_priv_srv_key = fopen(filename_priv_srv_key, "wb");
	FILE *fp_pub_srv_key = fopen(filename_pub_srv_key, "wb");
	
	if (fp_priv_srv_key == NULL) {
		perror("Cannot open the file for storing the private key.\n");
		exit(1);
	}
	if (fp_pub_srv_key == NULL) {
		perror("Cannot open the file for storing the public key.\n");
		exit(1);
	}
	
	/*
	* Step 1: Generate random values, which are going to be the private key.
	*/
	ristretto255_point_t base;
	ristretto255_point_copy(&base, &ristretto255_point_base);
	
	unsigned char rand255[59][32];
	
	FILE *rand_src = fopen("/dev/urandom", "rb");
	if (rand_src == NULL) {
		perror("cannot open the random source.\n");
		exit(1);
	}
	
	for (int i = 0; i < 59; i++) {
		fread(rand255[i], 32, 1, rand_src);
	}
	
	ristretto255_scalar_t srv_sk[59];
	ristretto255_point_t srv_pk[59];
	
	ristretto255_point_add(&base, &base, &base); // 2
	ristretto255_point_add(&base, &base, &base); // 4
	ristretto255_point_add(&base, &base, &base); // 8
	
	for (int i = 0; i < 59; i++) {
		fread(rand255, sizeof(rand255), 1, rand_src);
		
		ristretto255_scalar_decode_long(&srv_sk[i], rand255[i], 32);
		
		ristretto255_point_scalarmul(&srv_pk[i], &base, &srv_sk[i]);
	}
	
	for (int i = 0; i < 59; i++) {
		fwrite(&srv_sk[i], sizeof(ristretto255_scalar_t), 1, fp_priv_srv_key);
		fwrite(&srv_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_srv_key);
	}
	
	fclose(fp_priv_srv_key);
	fclose(fp_pub_srv_key);
	fclose(rand_src);
}

void KeyGen_stage2(
		const char *filename_pub_1_key,
		const char *filename_pub_2_key,
		const char *filename_pub_key
) {
	FILE *fp_pub_1_key = fopen(filename_pub_1_key, "rb");
	FILE *fp_pub_2_key = fopen(filename_pub_2_key, "rb");
	FILE *fp_pub_key = fopen(filename_pub_key, "wb");
	
	if (fp_pub_1_key == NULL || fp_pub_2_key == NULL) {
		perror("Cannot open the file for reading the public keys.\n");
		exit(1);
	}
	
	if (fp_pub_key == NULL) {
		perror("Cannot open the file for storing the public keys.\n");
		exit(1);
	}
	
	ristretto255_point_t srv_1_pk[59];
	ristretto255_point_t srv_2_pk[59];
	ristretto255_point_t srv_pk[59];
	
	for (int i = 0; i < 59; i++) {
		fread(&srv_1_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_1_key);
		fread(&srv_2_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_2_key);
	}
	
	for (int i = 0; i < 59; i++) {
		ristretto255_point_add(&srv_pk[i], &srv_1_pk[i], &srv_2_pk[i]);
	}
	
	for (int i = 0; i < 59; i++) {
		fwrite(&srv_pk[i], sizeof(ristretto255_point_t), 1, fp_pub_key);
	}
	
	fclose(fp_pub_1_key);
	fclose(fp_pub_2_key);
	fclose(fp_pub_key);
}

void TablesGen(
		const char *filename_pub_1_key,
		const char *filename_pub_2_key,
		const char *filename_pub_key,
		const char *filename_pub_1_table_format,
		const char *filename_pub_2_table_format,
		const char *filename_pub_table_format
) {
	/*
	* Step 1: Generate random values, which are going to be the private key.
	*/
	ristretto255_point_t base;
	ristretto255_point_copy(&base, &ristretto255_point_base);
	
	ristretto255_point_t pk_1[59];
	ristretto255_point_t pk_2[59];
	ristretto255_point_t pk[59];
	
	ristretto255_point_add(&base, &base, &base); // 2
	ristretto255_point_add(&base, &base, &base); // 4
	ristretto255_point_add(&base, &base, &base); // 8
	
	FILE *fp_pub_1_key = fopen(filename_pub_1_key, "rb");
	FILE *fp_pub_2_key = fopen(filename_pub_2_key, "rb");
	FILE *fp_pub_key = fopen(filename_pub_key, "rb");
	
	if (fp_pub_1_key == NULL || fp_pub_2_key == NULL || fp_pub_key == NULL) {
		perror("Cannot open the file for reading the public keys.\n");
		exit(1);
	}
	
	for (int i = 0; i < 59; i++) {
		fread(&pk_1[i], sizeof(ristretto255_point_t), 1, fp_pub_1_key);
		fread(&pk_2[i], sizeof(ristretto255_point_t), 1, fp_pub_2_key);
		fread(&pk[i], sizeof(ristretto255_point_t), 1, fp_pub_key);
	}
	
	char filename[60][150];
	#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], filename_pub_1_table_format, i);
		TableGen(&pk_1[i], filename[i]);
	}
	sprintf(filename[59], filename_pub_1_table_format, 59);
	TableGen(&base, filename[59]);

	#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], filename_pub_2_table_format, i);
		TableGen(&pk_2[i], filename[i]);
	}
	sprintf(filename[59], filename_pub_2_table_format, 59);
	TableGen(&base, filename[59]);

	#pragma omp parallel for
	for (int i = 0; i < 59; i++) {
		sprintf(filename[i], filename_pub_table_format, i);
		TableGen(&pk[i], filename[i]);
	}
	sprintf(filename[59], filename_pub_table_format, 59);
	TableGen(&base, filename[59]);
}

void LoadPrivKey(ristretto255_scalar_t *psk, const char *filename_priv_key) {
	FILE *fp_priv_key = fopen(filename_priv_key, "rb");
	if (fp_priv_key == NULL) {
		perror("Cannot open the file for storing the private keys.\n");
		exit(1);
	}
	for (int i = 0; i < 59; i++) {
		fread(&psk[i], sizeof(ristretto255_scalar_t), 1, fp_priv_key);
	}
	fclose(fp_priv_key);
}

void LoadPubKey(ristretto255_point_t *ppk, const char *filename_pub_key) {
	FILE *fp_pub_key = fopen(filename_pub_key, "rb");
	if (fp_pub_key == NULL) {
		perror("Cannot open the file for storing the public keys.\n");
		exit(1);
	}
	for (int i = 0; i < 59; i++) {
		fread(&ppk[i], sizeof(ristretto255_point_t), 1, fp_pub_key);
	}
	fclose(fp_pub_key);
}

void Encrypt(ristretto255_point_t ct[60], const ristretto255_point_t pt[59], const fastecexp_state st_pk[60],
			 FILE *rand_src) {
	unsigned char rand255[32];
	fread(rand255, 32, 1, rand_src);

	TableCompute(&st_pk[59], &ct[59], rand255);
	for (int i = 0; i < 59; i++) {
		TableCompute(&st_pk[i], &ct[i], rand255);
	}

	for (int i = 0; i < 59; i++) {
		ristretto255_point_add(&ct[i], &ct[i], &pt[i]);
	}
}

/* Imporant: ct2 must differ from ct1 */
void
Rerand(ristretto255_point_t ct2[60], ristretto255_point_t ct1[60], const fastecexp_state st_pk[60], FILE *rand_src) {
	unsigned char rand255[32];
	fread(rand255, 32, 1, rand_src);

	TableCompute(&st_pk[59], &ct2[59], rand255);
	for (int i = 0; i < 59; i++) {
		TableCompute(&st_pk[i], &ct2[i], rand255);
	}

	for (int i = 0; i < 60; i++) {
		ristretto255_point_add(&ct2[i], &ct2[i], &ct1[i]);
	}
}

void Rerand_to_cache(ristretto255_point_t ct[60], const fastecexp_state st_pk[60], FILE *rand_src) {
	unsigned char rand255[32];
	fread(rand255, 32, 1, rand_src);

	TableCompute(&st_pk[59], &ct[59], rand255);
	for (int i = 0; i < 59; i++) {
		TableCompute(&st_pk[i], &ct[i], rand255);
	}
}

void Rerand_use_cache(ristretto255_point_t ct[60], ristretto255_point_t cache[60]) {
	for (int i = 0; i < 60; i++) {
		ristretto255_point_add(&ct[i], &ct[i], &cache[i]);
	}
}

void Decrypt(ristretto255_point_t pt[59], ristretto255_point_t ct[60], const ristretto255_scalar_t sk[59]) {
	for (int i = 0; i < 59; i++) {
		ristretto255_point_scalarmul(&pt[i], &ct[59], &sk[i]);
		ristretto255_point_sub(&pt[i], &ct[i], &pt[i]);
	}
}

/* now must rerandomize before decryption */
void PartDec1(ristretto255_point_t ct_short[1], ristretto255_point_t ct[60]) {
	ristretto255_point_copy(&ct_short[0], &ct[59]);
}

void PartDec2(ristretto255_point_t pt[59], ristretto255_point_t ct_short[1], const ristretto255_scalar_t sk[59]) {
	for (int i = 0; i < 59; i++) {
		ristretto255_point_scalarmul(&pt[i], &ct_short[0], &sk[i]);
	}
}

void PartDec3(ristretto255_point_t ct_dest[59], ristretto255_point_t ct_src[59]) {
	for (int i = 0; i < 59; i++) {
		ristretto255_point_sub(&ct_dest[i], &ct_src[i], &ct_dest[i]);
	}
}

size_t Serialize_Honest_Size(int num_of_points) {
	return SER_BYTES * 2 * num_of_points;
}

void Serialize_Honest(unsigned char *out, ristretto255_point_t *in, int num_of_points) {
	uint8_t *serialized_output = out;

	gf_25519_t *table = malloc(sizeof(gf_25519_t) * 2 * num_of_points);
	gf_25519_t *zs = malloc(sizeof(gf_25519_t) * num_of_points);
	gf_25519_t *zis = malloc(sizeof(gf_25519_t) * num_of_points);

	if (zs == NULL || zis == NULL) {
		perror("Cannot create space to store the z and its inverse.");
		exit(1);
	}

	for (int i = 0; i < num_of_points; i++) {
		gf_copy(&table[i * 2], &in[i].x);
		gf_copy(&table[i * 2 + 1], &in[i].y);
		gf_copy(&zs[i], &in[i].z);
	}

	gf_batch_invert_here(zis, zs, num_of_points);

	int num_threads = omp_get_max_threads();
	gf_25519_t product[num_threads];

#pragma omp parallel for
	for (int i = 0; i < num_of_points; i++) {
		int current_thread_num = omp_get_thread_num();

		gf_25519_t *pp = &product[current_thread_num];

		gf_mul(pp, &table[2 * i], &zis[i]);
		gf_strong_reduce(pp);
		gf_copy(&table[2 * i], pp);

		gf_mul(pp, &table[2 * i + 1], &zis[i]);
		gf_strong_reduce(pp);
		gf_copy(&table[2 * i + 1], pp);
	}

	free(zis);
	free(zs);

#pragma omp parallel for
	for (int i = 0; i < 2 * num_of_points; i++) {
		gf_serialize(&serialized_output[i * SER_BYTES], &table[i], 1);
	}
}

size_t Serialize_Honest_Size_old(int num_of_points) {
	return sizeof(gf_25519_t) * 2 * num_of_points;
}

void Serialize_Honest_old(unsigned char *out, ristretto255_point_t *in, int num_of_points) {
	gf_25519_t *table = (gf_25519_t *) out;

	gf_25519_t *zs = malloc(sizeof(gf_25519_t) * num_of_points);
	gf_25519_t *zis = malloc(sizeof(gf_25519_t) * num_of_points);

	if (zs == NULL || zis == NULL) {
		perror("\033[0;31m[ERROR]\033[0m Cannot create space to store the z and its inverse.");
		exit(1);
	}

	for (int i = 0; i < num_of_points; i++) {
		gf_copy(&table[i * 2], &in[i].x);
		gf_copy(&table[i * 2 + 1], &in[i].y);
		gf_copy(&zs[i], &in[i].z);
	}

	gf_batch_invert_here(zis, zs, num_of_points);

	int num_threads = omp_get_max_threads();
	gf_25519_t product[num_threads];

#pragma omp parallel for
	for (int i = 0; i < num_of_points; i++) {
		int current_thread_num = omp_get_thread_num();

		gf_25519_t *pp = &product[current_thread_num];

		gf_mul(pp, &table[2 * i], &zis[i]);
		gf_strong_reduce(pp);
		gf_copy(&table[2 * i], pp);

		gf_mul(pp, &table[2 * i + 1], &zis[i]);
		gf_strong_reduce(pp);
		gf_copy(&table[2 * i + 1], pp);
	}

	free(zis);
	free(zs);
}

void Deserialize_Honest(ristretto255_point_t *out, unsigned char *in, int num_of_points) {
	int num_threads = omp_get_max_threads();
	gf_25519_t a[num_threads];
	gf_25519_t b[num_threads];

#pragma omp parallel for
	for (int i = 0; i < num_of_points; i++) {
		int current_thread_num = omp_get_thread_num();

		gf_deserialize(&a[current_thread_num], &in[i * SER_BYTES * 2], 1, 0);
		gf_deserialize(&b[current_thread_num], &in[i * SER_BYTES * 2 + SER_BYTES], 1, 0);

		gf_copy(&out[i].x, &a[current_thread_num]);
		gf_copy(&out[i].y, &b[current_thread_num]);
		gf_mul(&out[i].t, &out[i].x, &out[i].y);
		gf_copy(&out[i].z, &ONE);
	}
}

void Deserialize_Honest_old(ristretto255_point_t *out, unsigned char *in, int num_of_points) {
	int num_threads = omp_get_max_threads();
	gf_25519_t a[num_threads];
	gf_25519_t b[num_threads];

#pragma omp parallel for
	for (int i = 0; i < num_of_points; i++) {
		int current_thread_num = omp_get_thread_num();

		memcpy(&a[current_thread_num], &in[i * sizeof(gf_25519_t) * 2], sizeof(gf_25519_t));
		memcpy(&b[current_thread_num], &in[i * sizeof(gf_25519_t) * 2 + sizeof(gf_25519_t)], sizeof(gf_25519_t));

		gf_copy(&out[i].x, &a[current_thread_num]);
		gf_copy(&out[i].y, &b[current_thread_num]);
		gf_mul(&out[i].t, &out[i].x, &out[i].y);
		gf_copy(&out[i].z, &ONE);
	}
}

size_t Serialize_Malicious_Size(int num_of_points) {
	return 32 * num_of_points;
}

void Serialize_Malicious(unsigned char *out, ristretto255_point_t *in, int num_of_points) {
#pragma omp parallel for
	for (int i = 0; i < num_of_points; i++) {
		ristretto255_point_encode(&out[32 * i], &in[i]);
	}
}

ristretto_error_t Deserialize_Malicious(ristretto255_point_t *out, unsigned char *in, int num_of_points) {
	int num_threads = omp_get_max_threads();
	ristretto_error_t flag[num_threads];
	ristretto_error_t flag_tmp[num_threads];

	for (int i = 0; i < num_threads; i++) {
		flag[i] = RISTRETTO_SUCCESS;
	}

#pragma omp parallel for
	for (int i = 0; i < num_of_points; i++) {
		int current_thread_num = omp_get_thread_num();

		flag_tmp[current_thread_num] = ristretto255_point_decode(&out[i], &in[i * 32], RISTRETTO_TRUE);

		flag[current_thread_num] &= flag_tmp[current_thread_num];
	}

	ristretto_error_t final_flag = RISTRETTO_SUCCESS;
	for (int i = 0; i < num_threads; i++) {
		final_flag &= flag[i];
	}

	return final_flag;
}
