#include <ristretto_elgamal.h>
#include "word.h"
#include "field.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define scalar_t ristretto255_scalar_t
#define point_t ristretto255_point_t
extern const int RISTRETTO255_EDWARDS_D;
extern const gf_25519_t RISTRETTO255_FACTOR;
#define TWISTED_D (-(RISTRETTO255_EDWARDS_D))
#define EDWARDS_D RISTRETTO255_EDWARDS_D

void ristretto_elgamal_decode_single_message_hintless_hashonly(
		const point_t *p,
		unsigned char ser[SER_BYTES]
) {
	/*
	* will return the whole ser including the hash value.
	* the encoding will skip the first bit and the last bit
	* so this algorithm will place the hash value as the last valid 80 bits
	*/

	/* Try to figure out the other two masks */
	gf_25519_t t1, t2, t3, t4, t5;
	gf_add(&t1, &p->z, &p->y);
	gf_sub(&t2, &p->z, &p->y);
	gf_mul(&t3, &t1, &t2);     /* t3 = num */
	gf_mul(&t2, &p->x, &p->y); /* t2 = den */
	gf_sqr(&t1, &t2);
	gf_mul(&t4, &t1, &t3);
	gf_mulw(&t1, &t4, -1 - TWISTED_D);
	gf_isr(&t4, &t1);         /* isqrt(num*(a-d)*den^2) */
	gf_mul(&t1, &t2, &t4);
	gf_mul(&t2, &t1, &RISTRETTO255_FACTOR); /* t2 = "iden" in ristretto.sage */
	gf_mul(&t1, &t3, &t4);                  /* t1 = "inum" in ristretto.sage */

	/* Calculate altxy = iden*inum*i*t^2*(d-a) */
	gf_mul(&t3, &t1, &t2);
	gf_mul_i(&t4, &t3);
	gf_mul(&t3, &t4, &p->t);
	gf_mul(&t4, &t3, &p->t);
	gf_mulw(&t3, &t4, TWISTED_D + 1);         /* iden*inum*i*t^2*(d-1) */

	mask_t rotate_0 = gf_lobit(&t3);
	mask_t rotate_1 = ~rotate_0;

	gf_25519_t t1_rotate_0, t2_rotate_0;
	gf_25519_t t1_rotate_1, t2_rotate_1;
	gf_copy(&t1_rotate_0, &t1);
	gf_copy(&t2_rotate_0, &t2);
	gf_copy(&t1_rotate_1, &t1);
	gf_copy(&t2_rotate_1, &t2);

	gf_cond_swap(&t1_rotate_0, &t2_rotate_0, rotate_0);
	gf_cond_swap(&t1_rotate_1, &t2_rotate_1, rotate_1);

	gf_25519_t t4_rotate_0, t4_rotate_1;
	gf_mul_i(&t4_rotate_0, &p->x);
	gf_mul_i(&t4_rotate_1, &p->x);

	gf_cond_sel(&t4_rotate_0, &p->y, &t4_rotate_0, rotate_0);
	gf_cond_sel(&t4_rotate_1, &p->y, &t4_rotate_1, rotate_1);

	gf_mul_i(&t5, &RISTRETTO255_FACTOR);  /* t5 = imi */
	gf_25519_t t3_rotate_0, t3_rotate_1;
	gf_25519_t t5_rotate_0, t5_rotate_1;
	gf_mul(&t3_rotate_0, &t5, &t2_rotate_0);
	gf_mul(&t3_rotate_1, &t5, &t2_rotate_1);
	gf_mul(&t2_rotate_0, &t5, &t1_rotate_0);
	gf_mul(&t2_rotate_1, &t5, &t1_rotate_1);
	gf_mul(&t5_rotate_0, &t2_rotate_0, &p->t);
	gf_mul(&t5_rotate_1, &t2_rotate_1, &p->t);

	mask_t negx_rotate_0_altx_0 = gf_lobit(&t5_rotate_0);
	mask_t negx_rotate_0_altx_1 = ~negx_rotate_0_altx_0;
	mask_t negx_rotate_1_altx_0 = gf_lobit(&t5_rotate_1);
	mask_t negx_rotate_1_altx_1 = ~negx_rotate_1_altx_0;

	gf_25519_t t1_rotate_0_altx_0, t1_rotate_0_altx_1, t1_rotate_1_altx_0, t1_rotate_1_altx_1;
	gf_copy(&t1_rotate_0_altx_0, &t1_rotate_0);
	gf_copy(&t1_rotate_0_altx_1, &t1_rotate_0);
	gf_copy(&t1_rotate_1_altx_0, &t1_rotate_1);
	gf_copy(&t1_rotate_1_altx_1, &t1_rotate_1);

	gf_cond_neg(&t1_rotate_0_altx_0, rotate_0 ^ negx_rotate_0_altx_0);
	gf_cond_neg(&t1_rotate_0_altx_1, rotate_0 ^ negx_rotate_0_altx_1);
	gf_cond_neg(&t1_rotate_1_altx_0, rotate_1 ^ negx_rotate_1_altx_0);
	gf_cond_neg(&t1_rotate_1_altx_1, rotate_1 ^ negx_rotate_1_altx_1);

	gf_25519_t t2_rotate_0_altx_0, t2_rotate_0_altx_1, t2_rotate_1_altx_0, t2_rotate_1_altx_1;

	gf_mul(&t2_rotate_0_altx_0, &t1_rotate_0_altx_0, &p->z);
	gf_mul(&t2_rotate_0_altx_1, &t1_rotate_0_altx_1, &p->z);
	gf_mul(&t2_rotate_1_altx_0, &t1_rotate_1_altx_0, &p->z);
	gf_mul(&t2_rotate_1_altx_1, &t1_rotate_1_altx_1, &p->z);

	gf_add(&t2_rotate_0_altx_0, &t2_rotate_0_altx_0, &ONE);
	gf_add(&t2_rotate_0_altx_1, &t2_rotate_0_altx_1, &ONE);
	gf_add(&t2_rotate_1_altx_0, &t2_rotate_1_altx_0, &ONE);
	gf_add(&t2_rotate_1_altx_1, &t2_rotate_1_altx_1, &ONE);

	gf_25519_t inv_el_sum_rotate_0;
	gf_25519_t inv_el_sum_rotate_1;
	gf_mul(&inv_el_sum_rotate_0, &t3_rotate_0, &t4_rotate_0);
	gf_mul(&inv_el_sum_rotate_1, &t3_rotate_1, &t4_rotate_1);

	gf_25519_t s_rotate_0_altx_0;
	gf_25519_t s_rotate_0_altx_1;
	gf_25519_t s_rotate_1_altx_0;
	gf_25519_t s_rotate_1_altx_1;
	gf_mul(&s_rotate_0_altx_0, &inv_el_sum_rotate_0, &t2_rotate_0_altx_0);
	gf_mul(&s_rotate_0_altx_1, &inv_el_sum_rotate_0, &t2_rotate_0_altx_1);
	gf_mul(&s_rotate_1_altx_0, &inv_el_sum_rotate_1, &t2_rotate_1_altx_0);
	gf_mul(&s_rotate_1_altx_1, &inv_el_sum_rotate_1, &t2_rotate_1_altx_1);

	mask_t negs_rotate_0_altx_0 = gf_lobit(&s_rotate_0_altx_0);
	mask_t negs_rotate_0_altx_1 = gf_lobit(&s_rotate_0_altx_1);
	mask_t negs_rotate_1_altx_0 = gf_lobit(&s_rotate_1_altx_0);
	mask_t negs_rotate_1_altx_1 = gf_lobit(&s_rotate_1_altx_1);

	gf_cond_neg(&s_rotate_0_altx_0, negs_rotate_0_altx_0);
	gf_cond_neg(&s_rotate_0_altx_1, negs_rotate_0_altx_1);
	gf_cond_neg(&s_rotate_1_altx_0, negs_rotate_1_altx_0);
	gf_cond_neg(&s_rotate_1_altx_1, negs_rotate_1_altx_1);

	gf_25519_t inv_el_sum_rotate_0_altx_0;
	gf_25519_t inv_el_sum_rotate_0_altx_1;
	gf_25519_t inv_el_sum_rotate_1_altx_0;
	gf_25519_t inv_el_sum_rotate_1_altx_1;
	gf_mul(&inv_el_sum_rotate_0_altx_0, &t2_rotate_0_altx_0, &t4_rotate_0);
	gf_mul(&inv_el_sum_rotate_0_altx_1, &t2_rotate_0_altx_1, &t4_rotate_0);
	gf_mul(&inv_el_sum_rotate_1_altx_0, &t2_rotate_1_altx_0, &t4_rotate_1);
	gf_mul(&inv_el_sum_rotate_1_altx_1, &t2_rotate_1_altx_1, &t4_rotate_1);

	mask_t negz_rotate_0_altx_0 = (~negs_rotate_0_altx_0) ^negx_rotate_0_altx_0;
	mask_t negz_rotate_0_altx_1 = (~negs_rotate_0_altx_1) ^negx_rotate_0_altx_1;
	mask_t negz_rotate_1_altx_0 = (~negs_rotate_1_altx_0) ^negx_rotate_1_altx_0;
	mask_t negz_rotate_1_altx_1 = (~negs_rotate_1_altx_1) ^negx_rotate_1_altx_1;

	gf_25519_t inv_el_m1_rotate_0_altx_0;
	gf_25519_t inv_el_m1_rotate_0_altx_1;
	gf_25519_t inv_el_m1_rotate_1_altx_0;
	gf_25519_t inv_el_m1_rotate_1_altx_1;

	gf_copy(&inv_el_m1_rotate_0_altx_0, &p->z);
	gf_copy(&inv_el_m1_rotate_0_altx_1, &p->z);
	gf_copy(&inv_el_m1_rotate_1_altx_0, &p->z);
	gf_copy(&inv_el_m1_rotate_1_altx_1, &p->z);

	gf_25519_t inv_el_m1_rotate_0_altx_0_sgn_0, inv_el_m1_rotate_0_altx_0_sgn_1,
			inv_el_m1_rotate_0_altx_1_sgn_0, inv_el_m1_rotate_0_altx_1_sgn_1,
			inv_el_m1_rotate_1_altx_0_sgn_0, inv_el_m1_rotate_1_altx_0_sgn_1,
			inv_el_m1_rotate_1_altx_1_sgn_0, inv_el_m1_rotate_1_altx_1_sgn_1;

	gf_copy(&inv_el_m1_rotate_0_altx_0_sgn_0, &inv_el_m1_rotate_0_altx_0);
	gf_copy(&inv_el_m1_rotate_0_altx_1_sgn_0, &inv_el_m1_rotate_0_altx_1);
	gf_copy(&inv_el_m1_rotate_1_altx_0_sgn_0, &inv_el_m1_rotate_1_altx_0);
	gf_copy(&inv_el_m1_rotate_1_altx_1_sgn_0, &inv_el_m1_rotate_1_altx_1);
	gf_copy(&inv_el_m1_rotate_0_altx_0_sgn_1, &inv_el_m1_rotate_0_altx_0);
	gf_copy(&inv_el_m1_rotate_0_altx_1_sgn_1, &inv_el_m1_rotate_0_altx_1);
	gf_copy(&inv_el_m1_rotate_1_altx_0_sgn_1, &inv_el_m1_rotate_1_altx_0);
	gf_copy(&inv_el_m1_rotate_1_altx_1_sgn_1, &inv_el_m1_rotate_1_altx_1);

	gf_cond_neg(&inv_el_m1_rotate_0_altx_0_sgn_0, negz_rotate_0_altx_0);
	gf_cond_neg(&inv_el_m1_rotate_0_altx_1_sgn_0, negz_rotate_0_altx_1);
	gf_cond_neg(&inv_el_m1_rotate_1_altx_0_sgn_0, negz_rotate_1_altx_0);
	gf_cond_neg(&inv_el_m1_rotate_1_altx_1_sgn_0, negz_rotate_1_altx_1);

	gf_sub(&inv_el_m1_rotate_0_altx_0_sgn_1, &ZERO, &inv_el_m1_rotate_0_altx_0_sgn_0);
	gf_sub(&inv_el_m1_rotate_0_altx_1_sgn_1, &ZERO, &inv_el_m1_rotate_0_altx_1_sgn_0);
	gf_sub(&inv_el_m1_rotate_1_altx_0_sgn_1, &ZERO, &inv_el_m1_rotate_1_altx_0_sgn_0);
	gf_sub(&inv_el_m1_rotate_1_altx_1_sgn_1, &ZERO, &inv_el_m1_rotate_1_altx_1_sgn_0);

	gf_sub(&inv_el_m1_rotate_0_altx_0_sgn_0, &inv_el_m1_rotate_0_altx_0_sgn_0, &t4_rotate_0);
	gf_sub(&inv_el_m1_rotate_0_altx_1_sgn_0, &inv_el_m1_rotate_0_altx_1_sgn_0, &t4_rotate_0);
	gf_sub(&inv_el_m1_rotate_1_altx_0_sgn_0, &inv_el_m1_rotate_1_altx_0_sgn_0, &t4_rotate_1);
	gf_sub(&inv_el_m1_rotate_1_altx_1_sgn_0, &inv_el_m1_rotate_1_altx_1_sgn_0, &t4_rotate_1);

	gf_sub(&inv_el_m1_rotate_0_altx_0_sgn_1, &inv_el_m1_rotate_0_altx_0_sgn_1, &t4_rotate_0);
	gf_sub(&inv_el_m1_rotate_0_altx_1_sgn_1, &inv_el_m1_rotate_0_altx_1_sgn_1, &t4_rotate_0);
	gf_sub(&inv_el_m1_rotate_1_altx_0_sgn_1, &inv_el_m1_rotate_1_altx_0_sgn_1, &t4_rotate_1);
	gf_sub(&inv_el_m1_rotate_1_altx_1_sgn_1, &inv_el_m1_rotate_1_altx_1_sgn_1, &t4_rotate_1);

	gf_25519_t a[8];
	gf_25519_t b[8];
	gf_25519_t c[8];

	b[0] = inv_el_sum_rotate_0_altx_0;
	b[1] = inv_el_sum_rotate_0_altx_0;

	b[2] = inv_el_sum_rotate_0_altx_1;
	b[3] = inv_el_sum_rotate_0_altx_1;

	b[4] = inv_el_sum_rotate_1_altx_0;
	b[5] = inv_el_sum_rotate_1_altx_0;

	b[6] = inv_el_sum_rotate_1_altx_1;
	b[7] = inv_el_sum_rotate_1_altx_1;

	c[0] = inv_el_m1_rotate_0_altx_0_sgn_0;
	c[1] = inv_el_m1_rotate_0_altx_0_sgn_1;

	c[2] = inv_el_m1_rotate_0_altx_1_sgn_0;
	c[3] = inv_el_m1_rotate_0_altx_1_sgn_1;

	c[4] = inv_el_m1_rotate_1_altx_0_sgn_0;
	c[5] = inv_el_m1_rotate_1_altx_0_sgn_1;

	c[6] = inv_el_m1_rotate_1_altx_1_sgn_0;
	c[7] = inv_el_m1_rotate_1_altx_1_sgn_1;

	uint8_t recovered_data[8][SER_BYTES];

	mask_t is_identity = gf_eq(&p->t, &ZERO);
	/* Terrible, terrible special casing due to lots of 0/0 is deisogenize
	 * Basically we need to generate -D and +- i*RISTRETTO255_FACTOR
	 */
	for (int ind = 0; ind < 8; ind++) {
		/*
		* sgn_s = ind & 1
		* sgn_altx = (ind >> 1) & 1
		* sgn_ed_T = (ind >> 2) & 1
		*/

		mask_t sgn_altx = -((ind >> 1) & 1);
		mask_t sgn_ed_T = -((ind >> 2) & 1);

		gf_mul_i(&a[ind], &RISTRETTO255_FACTOR);
		gf_cond_sel(&b[ind], &b[ind], &ONE, is_identity);
		gf_cond_neg(&a[ind], sgn_altx);
		gf_cond_sel(&c[ind], &c[ind], &a[ind], is_identity & sgn_ed_T);
		gf_cond_sel(&c[ind], &c[ind], &ZERO, is_identity & ~sgn_ed_T);
		gf_mulw(&a[ind], &ONE, -EDWARDS_D);
		gf_cond_sel(&c[ind], &c[ind], &a[ind], is_identity & ~sgn_ed_T & ~sgn_altx);
	}

	uint8_t recovered_plaintext[8][SER_BYTES];
	uint8_t plaintext_hash[8][10];

	for (int ind = 0; ind < 8; ind++) {
		mask_t sgn_s = -(ind & 1);

		gf_mulw(&a[ind], &b[ind], -EDWARDS_D);
		gf_add(&b[ind], &a[ind], &b[ind]);
		gf_sub(&a[ind], &a[ind], &c[ind]);
		gf_add(&b[ind], &b[ind], &c[ind]);
		gf_cond_swap(&a[ind], &b[ind], sgn_s);
		gf_mul_qnr(&c[ind], &b[ind]);
		gf_mul(&b[ind], &c[ind], &a[ind]);
		mask_t succ = gf_isr(&c[ind], &b[ind]);
		succ |= gf_eq(&b[ind], &ZERO);
		gf_mul(&b[ind], &c[ind], &a[ind]);

		gf_cond_neg(&b[ind], gf_lobit(&b[ind]));

		gf_serialize(recovered_data[ind], &b[ind], 1);

		shift_to_lower_index(1, recovered_data[ind], recovered_data[ind], SER_BYTES);

		memcpy(plaintext_hash[ind], &recovered_data[ind][0], 10);
		memset(recovered_plaintext[ind], 0, SER_BYTES);
		memcpy(recovered_plaintext[ind], &recovered_data[ind][10], 22);

		/* Compute the hash of ser[0...21] 22 bytes */
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha256_handle;
		SHA256_Init(&sha256_handle);
		SHA256_Update(&sha256_handle, recovered_plaintext[ind], 22);
		SHA256_Final(hash, &sha256_handle);

		uint8_t comparison = constant_time_memcmp(hash, plaintext_hash[ind], 10);
		for (int i = 0; i < 22; i++) {
			ser[i] |= recovered_plaintext[ind][i] & comparison;
		}
	}
}
