#include <ristretto_elgamal.h>
#include "word.h"
#include "field.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
* This executable program runs and observes some values during the elligator and the inverse elligator
*/

#define scalar_t ristretto255_scalar_t
#define point_t ristretto255_point_t
extern const int RISTRETTO255_EDWARDS_D;
extern const gf_25519_t RISTRETTO255_FACTOR;
#define TWISTED_D (-(RISTRETTO255_EDWARDS_D))
#define EDWARDS_D RISTRETTO255_EDWARDS_D

void ristretto_elgamal_encode_message_directly_test(
		point_t *p,
		const unsigned char ser[SER_BYTES],
		mask_t *sgn_ed_T,
		mask_t *sgn_altx,
		mask_t *sgn_s
);

void ristretto_elgamal_encode_message_directly_test(
		point_t *p,
		const unsigned char ser[SER_BYTES],
		mask_t *sgn_ed_T,
		mask_t *sgn_altx,
		mask_t *sgn_s
) {
	printf("\033[0;32m[INFO]\033[0m As follows, we will print some values, which reflect the corresponding variables in the elligator algorithm description.\n");

	/* Computer r = i * r0 ^ 2
	** To ensure that we can have one r0, the caller needs to set r0 to be positive (not negative),
	** such that r0 is the positive square root of r / i.
	*/
	gf_25519_t r0, r, a, b, c, N, e;
	const uint8_t mask = (uint8_t)(0xFE << (6));
	ignore_result(gf_deserialize(&r0, ser, 0, mask));
	gf_strong_reduce(&r0);
	ristretto_elgamal_gf_25519_t_printf("r0", &r0);

	gf_sqr(&a, &r0);
	gf_mul_qnr(&r, &a);

	ristretto_elgamal_gf_25519_t_printf("r", &r);

	/* Compute D@c := (dr+a-d)(dr-ar-d) with a=1 */
	gf_sub(&a, &r, &ONE);
	gf_mulw(&b, &a, EDWARDS_D); /* dr-d */
	gf_add(&a, &b, &ONE);
	gf_sub(&b, &b, &r);
	gf_mul(&c, &a, &b);

	ristretto_elgamal_gf_25519_t_printf("D", &c);

	/* compute N := (r+1)(a-2d) */
	gf_add(&a, &r, &ONE);
	gf_mulw(&N, &a, 1 - 2 * EDWARDS_D);

	ristretto_elgamal_gf_25519_t_printf("N", &N);

	/* e = +-sqrt(1/ND) or +-r0 * sqrt(qnr/ND) */
	gf_mul(&a, &c, &N);
	mask_t square = gf_isr(&b, &a);
	gf_cond_sel(&c, &r0, &ONE, square); /* r? = square ? 1 : r0 */
	gf_mul(&e, &b, &c);

	ristretto_elgamal_gf_25519_t_printf("e", &e);

	/* s@a = +-|N.e| */
	gf_mul(&a, &N, &e);
	gf_cond_neg(&a, gf_lobit(&a) ^ ~square);

	ristretto_elgamal_gf_25519_t_printf("\ns", &a);

	gf_25519_t saved_s;
	gf_copy(&saved_s, &a);

	/* t@b = -+ cN(r-1)((a-2d)e)^2 - 1 */
	gf_mulw(&c, &e, 1 - 2 * EDWARDS_D); /* (a-2d)e */
	gf_sqr(&b, &c);
	gf_sub(&e, &r, &ONE);
	gf_mul(&c, &b, &e);
	gf_mul(&b, &c, &N);
	gf_cond_neg(&b, square);
	gf_sub(&b, &b, &ONE);

	/* isogenize */
	gf_mul(&c, &a, &SQRT_MINUS_ONE);
	gf_copy(&a, &c);

	gf_sqr(&c, &a); /* s^2 */
	gf_add(&a, &a, &a); /* 2s */
	gf_add(&e, &c, &ONE);
	gf_mul(&p->t, &a, &e); /* 2s(1+s^2) */
	gf_mul(&p->x, &a, &b); /* 2st */
	gf_sub(&a, &ONE, &c);
	gf_mul(&p->y, &e, &a); /* (1+s^2)(1-s^2) */
	gf_mul(&p->z, &a, &b); /* (1-s^2)t */

	/* a small test */
	gf_25519_t THREE;
	gf_copy(&THREE, &ONE);
	gf_add(&THREE, &THREE, &ONE);
	gf_add(&THREE, &THREE, &ONE);

//	gf_sub(&THREE, &ZERO, &THREE);

	gf_mul(&a, &p->t, &THREE);
	gf_copy(&p->t, &a);

	gf_mul(&a, &p->x, &THREE);
	gf_copy(&p->x, &a);

	gf_mul(&a, &p->y, &THREE);
	gf_copy(&p->y, &a);

	gf_mul(&a, &p->z, &THREE);
	gf_copy(&p->z, &a);

	/* Reveal the first mask: the sign of s has been decided by the result of gf_isr */
	*sgn_s = ~square;

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

	gf_cond_neg(&s_rotate_0_altx_0, negs_rotate_0_altx_0 ^ ~square);
	gf_cond_neg(&s_rotate_0_altx_1, negs_rotate_0_altx_1 ^ ~square);
	gf_cond_neg(&s_rotate_1_altx_0, negs_rotate_1_altx_0 ^ ~square);
	gf_cond_neg(&s_rotate_1_altx_1, negs_rotate_1_altx_1 ^ ~square);

	printf("\033[0;32m[INFO]\033[0m As follows, we will print some values, which reflect the corresponding variables in the inverse elligator algorithm when we do not know the three flag bits: rotate, altx, sgn.\n");

	ristretto_elgamal_gf_25519_t_printf("\ns_rotate_0_altx_0", &s_rotate_0_altx_0);
	ristretto_elgamal_gf_25519_t_printf("s_rotate_0_altx_1", &s_rotate_0_altx_1);
	ristretto_elgamal_gf_25519_t_printf("s_rotate_1_altx_0", &s_rotate_1_altx_0);
	ristretto_elgamal_gf_25519_t_printf("s_rotate_1_altx_1", &s_rotate_1_altx_1);

	gf_25519_t inv_el_sum_rotate_0_altx_0;
	gf_25519_t inv_el_sum_rotate_0_altx_1;
	gf_25519_t inv_el_sum_rotate_1_altx_0;
	gf_25519_t inv_el_sum_rotate_1_altx_1;
	gf_mul(&inv_el_sum_rotate_0_altx_0, &t2_rotate_0_altx_0, &t4_rotate_0);
	gf_mul(&inv_el_sum_rotate_0_altx_1, &t2_rotate_0_altx_1, &t4_rotate_0);
	gf_mul(&inv_el_sum_rotate_1_altx_0, &t2_rotate_1_altx_0, &t4_rotate_1);
	gf_mul(&inv_el_sum_rotate_1_altx_1, &t2_rotate_1_altx_1, &t4_rotate_1);

	ristretto_elgamal_gf_25519_t_printf("\ninv_el_sum_rotate_0_altx_0", &inv_el_sum_rotate_0_altx_0);
	ristretto_elgamal_gf_25519_t_printf("inv_el_sum_rotate_0_altx_1", &inv_el_sum_rotate_0_altx_1);
	ristretto_elgamal_gf_25519_t_printf("inv_el_sum_rotate_1_altx_0", &inv_el_sum_rotate_1_altx_0);
	ristretto_elgamal_gf_25519_t_printf("inv_el_sum_rotate_1_altx_1", &inv_el_sum_rotate_1_altx_1);

	mask_t succ_rotate_0_altx_1 = gf_eq(&saved_s, &s_rotate_0_altx_1);
	mask_t succ_rotate_1_altx_0 = gf_eq(&saved_s, &s_rotate_1_altx_0);
	mask_t succ_rotate_1_altx_1 = gf_eq(&saved_s, &s_rotate_1_altx_1);

	*sgn_ed_T = succ_rotate_1_altx_0 | succ_rotate_1_altx_1;
	*sgn_altx = succ_rotate_0_altx_1 | succ_rotate_1_altx_1;

	mask_t negz_rotate_0_altx_0 = (~negs_rotate_0_altx_0) ^(~square) ^negx_rotate_0_altx_0;
	mask_t negz_rotate_0_altx_1 = (~negs_rotate_0_altx_1) ^(~square) ^negx_rotate_0_altx_1;
	mask_t negz_rotate_1_altx_0 = (~negs_rotate_1_altx_0) ^(~square) ^negx_rotate_1_altx_0;
	mask_t negz_rotate_1_altx_1 = (~negs_rotate_1_altx_1) ^(~square) ^negx_rotate_1_altx_1;

	gf_25519_t inv_el_m1_rotate_0_altx_0;
	gf_25519_t inv_el_m1_rotate_0_altx_1;
	gf_25519_t inv_el_m1_rotate_1_altx_0;
	gf_25519_t inv_el_m1_rotate_1_altx_1;

	gf_copy(&inv_el_m1_rotate_0_altx_0, &p->z);
	gf_copy(&inv_el_m1_rotate_0_altx_1, &p->z);
	gf_copy(&inv_el_m1_rotate_1_altx_0, &p->z);
	gf_copy(&inv_el_m1_rotate_1_altx_1, &p->z);

	gf_cond_neg(&inv_el_m1_rotate_0_altx_0, negz_rotate_0_altx_0);
	gf_cond_neg(&inv_el_m1_rotate_0_altx_1, negz_rotate_0_altx_1);
	gf_cond_neg(&inv_el_m1_rotate_1_altx_0, negz_rotate_1_altx_0);
	gf_cond_neg(&inv_el_m1_rotate_1_altx_1, negz_rotate_1_altx_1);

	gf_sub(&inv_el_m1_rotate_0_altx_0, &inv_el_m1_rotate_0_altx_0, &t4_rotate_0);
	gf_sub(&inv_el_m1_rotate_0_altx_1, &inv_el_m1_rotate_0_altx_1, &t4_rotate_0);
	gf_sub(&inv_el_m1_rotate_1_altx_0, &inv_el_m1_rotate_1_altx_0, &t4_rotate_1);
	gf_sub(&inv_el_m1_rotate_1_altx_1, &inv_el_m1_rotate_1_altx_1, &t4_rotate_1);

	ristretto_elgamal_gf_25519_t_printf("\ninv_el_m1_rotate_0_altx_0", &inv_el_m1_rotate_0_altx_0);
	ristretto_elgamal_gf_25519_t_printf("inv_el_m1_rotate_0_altx_1", &inv_el_m1_rotate_0_altx_1);
	ristretto_elgamal_gf_25519_t_printf("inv_el_m1_rotate_1_altx_0", &inv_el_m1_rotate_1_altx_0);
	ristretto_elgamal_gf_25519_t_printf("inv_el_m1_rotate_1_altx_1", &inv_el_m1_rotate_1_altx_1);

	{
		gf_25519_t a, b, c;

		gf_copy(&b, &inv_el_sum_rotate_0_altx_0);
		gf_copy(&c, &inv_el_m1_rotate_0_altx_0);

		mask_t is_identity = gf_eq(&p->t, &ZERO);

		/* Terrible, terrible special casing due to lots of 0/0 is deisogenize
		 * Basically we need to generate -D and +- i*RISTRETTO255_FACTOR
		 */
		gf_mul_i(&a, &RISTRETTO255_FACTOR);
		gf_cond_sel(&b, &b, &ONE, is_identity);
		gf_cond_neg(&a, *sgn_altx);
		gf_cond_sel(&c, &c, &a, is_identity & *sgn_ed_T);
		gf_cond_sel(&c, &c, &ZERO, is_identity & ~*sgn_ed_T);
		gf_mulw(&a, &ONE, -EDWARDS_D);
		gf_cond_sel(&c, &c, &a, is_identity & ~*sgn_ed_T & ~*sgn_altx);

		gf_mulw(&a, &b, -EDWARDS_D);
		gf_add(&b, &a, &b);
		gf_sub(&a, &a, &c);
		gf_add(&b, &b, &c);
		gf_cond_swap(&a, &b, *sgn_s);
		gf_mul_qnr(&c, &b);
		gf_mul(&b, &c, &a);
		mask_t succ = gf_isr(&c, &b);
		succ |= gf_eq(&b, &ZERO);
		gf_mul(&b, &c, &a);

		gf_cond_neg(&b, gf_lobit(&b));

		ristretto_elgamal_gf_25519_t_printf("\nr0", &b);

		unsigned char recovered_hash[SER_BYTES];
		gf_serialize(recovered_hash, &b, 1);
		ristretto_elgamal_char_printf("  recovered_hash", recovered_hash);
	}

	{
		gf_25519_t a, b, c;

		gf_copy(&b, &inv_el_sum_rotate_0_altx_1);
		gf_copy(&c, &inv_el_m1_rotate_0_altx_1);

		mask_t is_identity = gf_eq(&p->t, &ZERO);

		/* Terrible, terrible special casing due to lots of 0/0 is deisogenize
		 * Basically we need to generate -D and +- i*RISTRETTO255_FACTOR
		 */
		gf_mul_i(&a, &RISTRETTO255_FACTOR);
		gf_cond_sel(&b, &b, &ONE, is_identity);
		gf_cond_neg(&a, *sgn_altx);
		gf_cond_sel(&c, &c, &a, is_identity & *sgn_ed_T);
		gf_cond_sel(&c, &c, &ZERO, is_identity & ~*sgn_ed_T);
		gf_mulw(&a, &ONE, -EDWARDS_D);
		gf_cond_sel(&c, &c, &a, is_identity & ~*sgn_ed_T & ~*sgn_altx);

		gf_mulw(&a, &b, -EDWARDS_D);
		gf_add(&b, &a, &b);
		gf_sub(&a, &a, &c);
		gf_add(&b, &b, &c);
		gf_cond_swap(&a, &b, *sgn_s);
		gf_mul_qnr(&c, &b);
		gf_mul(&b, &c, &a);
		mask_t succ = gf_isr(&c, &b);
		succ |= gf_eq(&b, &ZERO);
		gf_mul(&b, &c, &a);

		gf_cond_neg(&b, gf_lobit(&b));

		ristretto_elgamal_gf_25519_t_printf("r0", &b);

		unsigned char recovered_hash[SER_BYTES];
		gf_serialize(recovered_hash, &b, 1);
		ristretto_elgamal_char_printf("  recovered_hash", recovered_hash);
	}

	{
		gf_25519_t a, b, c;

		gf_copy(&b, &inv_el_sum_rotate_1_altx_0);
		gf_copy(&c, &inv_el_m1_rotate_1_altx_0);

		mask_t is_identity = gf_eq(&p->t, &ZERO);

		/* Terrible, terrible special casing due to lots of 0/0 is deisogenize
		 * Basically we need to generate -D and +- i*RISTRETTO255_FACTOR
		 */
		gf_mul_i(&a, &RISTRETTO255_FACTOR);
		gf_cond_sel(&b, &b, &ONE, is_identity);
		gf_cond_neg(&a, *sgn_altx);
		gf_cond_sel(&c, &c, &a, is_identity & *sgn_ed_T);
		gf_cond_sel(&c, &c, &ZERO, is_identity & ~*sgn_ed_T);
		gf_mulw(&a, &ONE, -EDWARDS_D);
		gf_cond_sel(&c, &c, &a, is_identity & ~*sgn_ed_T & ~*sgn_altx);

		gf_mulw(&a, &b, -EDWARDS_D);
		gf_add(&b, &a, &b);
		gf_sub(&a, &a, &c);
		gf_add(&b, &b, &c);
		gf_cond_swap(&a, &b, *sgn_s);
		gf_mul_qnr(&c, &b);
		gf_mul(&b, &c, &a);
		mask_t succ = gf_isr(&c, &b);
		succ |= gf_eq(&b, &ZERO);
		gf_mul(&b, &c, &a);

		gf_cond_neg(&b, gf_lobit(&b));

		ristretto_elgamal_gf_25519_t_printf("r0", &b);

		unsigned char recovered_hash[SER_BYTES];
		gf_serialize(recovered_hash, &b, 1);
		ristretto_elgamal_char_printf("  recovered_hash", recovered_hash);
	}

	{
		gf_25519_t a, b, c;

		gf_copy(&b, &inv_el_sum_rotate_1_altx_1);
		gf_copy(&c, &inv_el_m1_rotate_1_altx_1);

		mask_t is_identity = gf_eq(&p->t, &ZERO);

		/* Terrible, terrible special casing due to lots of 0/0 is deisogenize
		 * Basically we need to generate -D and +- i*RISTRETTO255_FACTOR
		 */
		gf_25519_t a_00, b_00;
		gf_mul_i(&a_00, &RISTRETTO255_FACTOR);
		gf_copy(&b_00, &ONE);

		gf_25519_t a_00_altx_0, a_00_altx_1;
		gf_copy(&a_00_altx_0, &a_00);
		gf_sub(&a_00_altx_1, &ZERO, &a_00);

		gf_25519_t c_00_altx_0_rotate_0, c_00_altx_0_rotate_1, c_00_altx_1_rotate_0, c_00_altx_1_rotate_1;
		gf_copy(&c_00_altx_1_rotate_0, &ZERO);
		gf_copy(&c_00_altx_0_rotate_1, &a_00_altx_0);
		gf_copy(&c_00_altx_1_rotate_1, &a_00_altx_1);

		gf_mulw(&a_00, &ONE, -EDWARDS_D);
		gf_copy(&c_00_altx_0_rotate_0, &a_00);

		gf_add(&b_00, &a_00, &b_00);

		gf_25519_t a_00_altx_0_rotate_0, a_00_altx_0_rotate_1, a_00_altx_1_rotate_0, a_00_altx_1_rotate_1;
		gf_sub(&a_00_altx_0_rotate_0, &a_00, &c_00_altx_0_rotate_0);
		gf_sub(&a_00_altx_0_rotate_1, &a_00, &c_00_altx_0_rotate_1);
		gf_sub(&a_00_altx_1_rotate_0, &a_00, &c_00_altx_1_rotate_0);
		gf_sub(&a_00_altx_1_rotate_1, &a_00, &c_00_altx_1_rotate_1);

		gf_25519_t b_00_altx_0_rotate_0, b_00_altx_0_rotate_1, b_00_altx_1_rotate_0, b_00_altx_1_rotate_1;
		gf_add(&b_00_altx_0_rotate_0, &b_00, &c_00_altx_0_rotate_0);
		gf_add(&b_00_altx_0_rotate_1, &b_00, &c_00_altx_0_rotate_1);
		gf_add(&b_00_altx_1_rotate_0, &b_00, &c_00_altx_1_rotate_0);
		gf_add(&b_00_altx_1_rotate_1, &b_00, &c_00_altx_1_rotate_1);

		gf_25519_t a_00_altx_0_rotate_0_sgn_0, a_00_altx_0_rotate_1_sgn_0, a_00_altx_1_rotate_0_sgn_0, a_00_altx_1_rotate_1_sgn_0,
				a_00_altx_0_rotate_0_sgn_1, a_00_altx_0_rotate_1_sgn_1, a_00_altx_1_rotate_0_sgn_1, a_00_altx_1_rotate_1_sgn_1;
		gf_25519_t b_00_altx_0_rotate_0_sgn_0, b_00_altx_0_rotate_1_sgn_0, b_00_altx_1_rotate_0_sgn_0, b_00_altx_1_rotate_1_sgn_0,
				b_00_altx_0_rotate_0_sgn_1, b_00_altx_0_rotate_1_sgn_1, b_00_altx_1_rotate_0_sgn_1, b_00_altx_1_rotate_1_sgn_1;
		gf_copy(&a_00_altx_0_rotate_0_sgn_0, &a_00_altx_0_rotate_0);
		gf_copy(&a_00_altx_0_rotate_1_sgn_0, &a_00_altx_0_rotate_1);
		gf_copy(&a_00_altx_1_rotate_0_sgn_0, &a_00_altx_1_rotate_0);
		gf_copy(&a_00_altx_1_rotate_1_sgn_0, &a_00_altx_1_rotate_1);
		gf_copy(&a_00_altx_0_rotate_0_sgn_1, &b_00_altx_0_rotate_0);
		gf_copy(&a_00_altx_0_rotate_1_sgn_1, &b_00_altx_0_rotate_1);
		gf_copy(&a_00_altx_1_rotate_0_sgn_1, &b_00_altx_1_rotate_0);
		gf_copy(&a_00_altx_1_rotate_1_sgn_1, &b_00_altx_1_rotate_1);

		gf_copy(&b_00_altx_0_rotate_0_sgn_0, &b_00_altx_0_rotate_0);
		gf_copy(&b_00_altx_0_rotate_1_sgn_0, &b_00_altx_0_rotate_1);
		gf_copy(&b_00_altx_1_rotate_0_sgn_0, &b_00_altx_1_rotate_0);
		gf_copy(&b_00_altx_1_rotate_1_sgn_0, &b_00_altx_1_rotate_1);
		gf_copy(&b_00_altx_0_rotate_0_sgn_1, &a_00_altx_0_rotate_0);
		gf_copy(&b_00_altx_0_rotate_1_sgn_1, &a_00_altx_0_rotate_1);
		gf_copy(&b_00_altx_1_rotate_0_sgn_1, &a_00_altx_1_rotate_0);
		gf_copy(&b_00_altx_1_rotate_1_sgn_1, &a_00_altx_1_rotate_1);

		gf_25519_t tmp_00_altx_0_rotate_0_sgn_0, tmp_00_altx_0_rotate_1_sgn_0, tmp_00_altx_1_rotate_0_sgn_0, tmp_00_altx_1_rotate_1_sgn_0,
				tmp_00_altx_0_rotate_0_sgn_1, tmp_00_altx_0_rotate_1_sgn_1, tmp_00_altx_1_rotate_0_sgn_1, tmp_00_altx_1_rotate_1_sgn_1;

		gf_mul(&tmp_00_altx_0_rotate_0_sgn_0, &b_00_altx_0_rotate_0_sgn_0, &r);
		gf_mul(&tmp_00_altx_0_rotate_1_sgn_0, &b_00_altx_0_rotate_1_sgn_0, &r);
		gf_mul(&tmp_00_altx_1_rotate_0_sgn_0, &b_00_altx_1_rotate_0_sgn_0, &r);
		gf_mul(&tmp_00_altx_1_rotate_1_sgn_0, &b_00_altx_1_rotate_1_sgn_0, &r);
		gf_mul(&tmp_00_altx_0_rotate_0_sgn_1, &b_00_altx_0_rotate_0_sgn_1, &r);
		gf_mul(&tmp_00_altx_0_rotate_1_sgn_1, &b_00_altx_0_rotate_1_sgn_1, &r);
		gf_mul(&tmp_00_altx_1_rotate_0_sgn_1, &b_00_altx_1_rotate_0_sgn_1, &r);
		gf_mul(&tmp_00_altx_1_rotate_1_sgn_1, &b_00_altx_1_rotate_1_sgn_1, &r);

		gf_sub(&tmp_00_altx_0_rotate_0_sgn_0, &tmp_00_altx_0_rotate_0_sgn_0, &a_00_altx_0_rotate_0_sgn_0);
		gf_sub(&tmp_00_altx_0_rotate_1_sgn_0, &tmp_00_altx_0_rotate_1_sgn_0, &a_00_altx_0_rotate_1_sgn_0);
		gf_sub(&tmp_00_altx_1_rotate_0_sgn_0, &tmp_00_altx_1_rotate_0_sgn_0, &a_00_altx_1_rotate_0_sgn_0);
		gf_sub(&tmp_00_altx_1_rotate_1_sgn_0, &tmp_00_altx_1_rotate_1_sgn_0, &a_00_altx_1_rotate_1_sgn_0);
		gf_sub(&tmp_00_altx_0_rotate_0_sgn_1, &tmp_00_altx_0_rotate_0_sgn_1, &a_00_altx_0_rotate_0_sgn_1);
		gf_sub(&tmp_00_altx_0_rotate_1_sgn_1, &tmp_00_altx_0_rotate_1_sgn_1, &a_00_altx_0_rotate_1_sgn_1);
		gf_sub(&tmp_00_altx_1_rotate_0_sgn_1, &tmp_00_altx_1_rotate_0_sgn_1, &a_00_altx_1_rotate_0_sgn_1);
		gf_sub(&tmp_00_altx_1_rotate_1_sgn_1, &tmp_00_altx_1_rotate_1_sgn_1, &a_00_altx_1_rotate_1_sgn_1);

		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_0_rotate_0_sgn_0", &tmp_00_altx_0_rotate_0_sgn_0);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_0_rotate_1_sgn_0", &tmp_00_altx_0_rotate_1_sgn_0);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_1_rotate_0_sgn_0", &tmp_00_altx_1_rotate_0_sgn_0);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_1_rotate_1_sgn_0", &tmp_00_altx_1_rotate_1_sgn_0);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_0_rotate_0_sgn_1", &tmp_00_altx_0_rotate_0_sgn_1);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_0_rotate_1_sgn_1", &tmp_00_altx_0_rotate_1_sgn_1);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_1_rotate_0_sgn_1", &tmp_00_altx_1_rotate_0_sgn_1);
		ristretto_elgamal_gf_25519_t_printf("tmp_00_altx_1_rotate_1_sgn_1", &tmp_00_altx_1_rotate_1_sgn_1);

		gf_25519_t c_00_altx_0_rotate_0_sgn_0, c_00_altx_0_rotate_1_sgn_0, c_00_altx_1_rotate_0_sgn_0, c_00_altx_1_rotate_1_sgn_0,
				c_00_altx_0_rotate_0_sgn_1, c_00_altx_0_rotate_1_sgn_1, c_00_altx_1_rotate_0_sgn_1, c_00_altx_1_rotate_1_sgn_1;
		gf_mul_qnr(&c_00_altx_0_rotate_0_sgn_0, &b_00_altx_0_rotate_0_sgn_0);
		gf_mul_qnr(&c_00_altx_0_rotate_1_sgn_0, &b_00_altx_0_rotate_1_sgn_0);
		gf_mul_qnr(&c_00_altx_1_rotate_0_sgn_0, &b_00_altx_1_rotate_0_sgn_0);
		gf_mul_qnr(&c_00_altx_1_rotate_1_sgn_0, &b_00_altx_1_rotate_1_sgn_0);
		gf_mul_qnr(&c_00_altx_0_rotate_0_sgn_1, &b_00_altx_0_rotate_0_sgn_1);
		gf_mul_qnr(&c_00_altx_0_rotate_1_sgn_1, &b_00_altx_0_rotate_1_sgn_1);
		gf_mul_qnr(&c_00_altx_1_rotate_0_sgn_1, &b_00_altx_1_rotate_0_sgn_1);
		gf_mul_qnr(&c_00_altx_1_rotate_1_sgn_1, &b_00_altx_1_rotate_1_sgn_1);

		gf_mul(&b_00_altx_0_rotate_0_sgn_0, &c_00_altx_0_rotate_0_sgn_0, &a_00_altx_0_rotate_0_sgn_0);
		gf_mul(&b_00_altx_0_rotate_1_sgn_0, &c_00_altx_0_rotate_1_sgn_0, &a_00_altx_0_rotate_1_sgn_0);
		gf_mul(&b_00_altx_1_rotate_0_sgn_0, &c_00_altx_1_rotate_0_sgn_0, &a_00_altx_1_rotate_0_sgn_0);
		gf_mul(&b_00_altx_1_rotate_1_sgn_0, &c_00_altx_1_rotate_1_sgn_0, &a_00_altx_1_rotate_1_sgn_0);
		gf_mul(&b_00_altx_0_rotate_0_sgn_1, &c_00_altx_0_rotate_0_sgn_1, &a_00_altx_0_rotate_0_sgn_1);
		gf_mul(&b_00_altx_0_rotate_1_sgn_1, &c_00_altx_0_rotate_1_sgn_1, &a_00_altx_0_rotate_1_sgn_1);
		gf_mul(&b_00_altx_1_rotate_0_sgn_1, &c_00_altx_1_rotate_0_sgn_1, &a_00_altx_1_rotate_0_sgn_1);
		gf_mul(&b_00_altx_1_rotate_1_sgn_1, &c_00_altx_1_rotate_1_sgn_1, &a_00_altx_1_rotate_1_sgn_1);

		gf_isr(&c_00_altx_0_rotate_0_sgn_0, &b_00_altx_0_rotate_0_sgn_0);
		gf_isr(&c_00_altx_0_rotate_1_sgn_0, &b_00_altx_0_rotate_1_sgn_0);
		gf_isr(&c_00_altx_1_rotate_0_sgn_0, &b_00_altx_1_rotate_0_sgn_0);
		gf_isr(&c_00_altx_1_rotate_1_sgn_0, &b_00_altx_1_rotate_1_sgn_0);
		gf_isr(&c_00_altx_0_rotate_0_sgn_1, &b_00_altx_0_rotate_0_sgn_1);
		gf_isr(&c_00_altx_0_rotate_1_sgn_1, &b_00_altx_0_rotate_1_sgn_1);
		gf_isr(&c_00_altx_1_rotate_0_sgn_1, &b_00_altx_1_rotate_0_sgn_1);
		gf_isr(&c_00_altx_1_rotate_1_sgn_1, &b_00_altx_1_rotate_1_sgn_1);

		gf_mul(&b_00_altx_0_rotate_0_sgn_0, &c_00_altx_0_rotate_0_sgn_0, &a_00_altx_0_rotate_0_sgn_0);
		gf_mul(&b_00_altx_0_rotate_1_sgn_0, &c_00_altx_0_rotate_1_sgn_0, &a_00_altx_0_rotate_1_sgn_0);
		gf_mul(&b_00_altx_1_rotate_0_sgn_0, &c_00_altx_1_rotate_0_sgn_0, &a_00_altx_1_rotate_0_sgn_0);
		gf_mul(&b_00_altx_1_rotate_1_sgn_0, &c_00_altx_1_rotate_1_sgn_0, &a_00_altx_1_rotate_1_sgn_0);
		gf_mul(&b_00_altx_0_rotate_0_sgn_1, &c_00_altx_0_rotate_0_sgn_1, &a_00_altx_0_rotate_0_sgn_1);
		gf_mul(&b_00_altx_0_rotate_1_sgn_1, &c_00_altx_0_rotate_1_sgn_1, &a_00_altx_0_rotate_1_sgn_1);
		gf_mul(&b_00_altx_1_rotate_0_sgn_1, &c_00_altx_1_rotate_0_sgn_1, &a_00_altx_1_rotate_0_sgn_1);
		gf_mul(&b_00_altx_1_rotate_1_sgn_1, &c_00_altx_1_rotate_1_sgn_1, &a_00_altx_1_rotate_1_sgn_1);

		gf_cond_neg(&b_00_altx_0_rotate_0_sgn_0, gf_lobit(&b_00_altx_0_rotate_0_sgn_0));
		gf_cond_neg(&b_00_altx_0_rotate_1_sgn_0, gf_lobit(&b_00_altx_0_rotate_0_sgn_0));
		gf_cond_neg(&b_00_altx_1_rotate_0_sgn_0, gf_lobit(&b_00_altx_0_rotate_0_sgn_0));
		gf_cond_neg(&b_00_altx_1_rotate_1_sgn_0, gf_lobit(&b_00_altx_0_rotate_0_sgn_0));
		gf_cond_neg(&b_00_altx_0_rotate_0_sgn_1, gf_lobit(&b_00_altx_0_rotate_0_sgn_1));
		gf_cond_neg(&b_00_altx_0_rotate_1_sgn_1, gf_lobit(&b_00_altx_0_rotate_1_sgn_1));
		gf_cond_neg(&b_00_altx_1_rotate_0_sgn_1, gf_lobit(&b_00_altx_1_rotate_0_sgn_1));
		gf_cond_neg(&b_00_altx_1_rotate_1_sgn_1, gf_lobit(&b_00_altx_1_rotate_1_sgn_1));

		/*	ristretto_elgamal_gf_25519_t_printf("b_00_altx_0_rotate_0_sgn_0", &b_00_altx_0_rotate_0_sgn_0);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_0_rotate_1_sgn_0", &b_00_altx_0_rotate_1_sgn_0);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_1_rotate_0_sgn_0", &b_00_altx_1_rotate_0_sgn_0);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_1_rotate_1_sgn_0", &b_00_altx_1_rotate_1_sgn_0);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_0_rotate_0_sgn_1", &b_00_altx_0_rotate_0_sgn_1);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_0_rotate_1_sgn_1", &b_00_altx_0_rotate_1_sgn_1);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_1_rotate_0_sgn_1", &b_00_altx_1_rotate_0_sgn_1);
			ristretto_elgamal_gf_25519_t_printf("b_00_altx_1_rotate_1_sgn_1", &b_00_altx_1_rotate_1_sgn_1);*/

		gf_mul_i(&a, &RISTRETTO255_FACTOR);
		gf_cond_sel(&b, &b, &ONE, is_identity);
		gf_cond_neg(&a, *sgn_altx);
		gf_cond_sel(&c, &c, &a, is_identity & *sgn_ed_T);
		gf_cond_sel(&c, &c, &ZERO, is_identity & ~*sgn_ed_T);
		gf_mulw(&a, &ONE, -EDWARDS_D);
		gf_cond_sel(&c, &c, &a, is_identity & ~*sgn_ed_T & ~*sgn_altx);

		gf_mulw(&a, &b, -EDWARDS_D);
		gf_add(&b, &a, &b);
		gf_sub(&a, &a, &c);
		gf_add(&b, &b, &c);
		gf_cond_swap(&a, &b, *sgn_s);
		gf_mul_qnr(&c, &b);
		gf_mul(&b, &c, &a);
		mask_t succ = gf_isr(&c, &b);
		succ |= gf_eq(&b, &ZERO);
		gf_mul(&b, &c, &a);

		gf_cond_neg(&b, gf_lobit(&b));

		ristretto_elgamal_gf_25519_t_printf("r0", &b);

		unsigned char recovered_hash[SER_BYTES];
		gf_serialize(recovered_hash, &b, 1);
		ristretto_elgamal_char_printf("  recovered_hash", recovered_hash);
	}
}

int main() {
	point_t test;
	uint8_t ser[SER_BYTES];
	mask_t sgn_ed_T, sgn_altx, sgn_s;

	memset(ser, 0, SER_BYTES);

	srand(time(0));
	for (int i = 0; i < SER_BYTES; i++) {
		ser[i] = rand() % 255;
	}

	ser[0] = ser[0] & (255 - 1);
	ser[SER_BYTES - 1] = ser[SER_BYTES - 1] & 127;

	ristretto_elgamal_char_printf("hash", ser);
	ristretto_elgamal_encode_message_directly_test(&test, ser, &sgn_ed_T, &sgn_altx, &sgn_s);
	return 0;
}
