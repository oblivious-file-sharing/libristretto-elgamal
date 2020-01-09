#include <ristretto_elgamal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern const int RISTRETTO255_EDWARDS_D;
extern const gf_25519_t RISTRETTO255_FACTOR;
#define TWISTED_D (-(RISTRETTO255_EDWARDS_D))
#define EDWARDS_D RISTRETTO255_EDWARDS_D

void ristretto_elgamal_encode_single_message(
		point_t *p,
		const unsigned char ser[SER_BYTES],
		mask_t *psgn_ed_T,
		mask_t *psgn_altx,
		mask_t *psgn_s
) {
	/*
	* Input requirement:
	* At least ser[0]'s lowest bit is 0 and ser[SER_BYTES - 1]'s highest bit is 0.
	*/
	assert((ser[0] & 1) == 0);
	assert((ser[SER_BYTES - 1] & 128) == 0);

	/* Computer r = i * r0 ^ 2
	** To ensure that we can have one r0, the caller needs to set r0 to be positive (not negative),
	** such that r0 is the positive square root of r / i.
	*/
	gf_25519_t r0, r, a, b, c, N, e;
	const uint8_t mask = (uint8_t)(0xFE << (6));
	ignore_result(gf_deserialize(&r0, ser, 0, mask));
	gf_strong_reduce(&r0);

	gf_sqr(&a, &r0);
	gf_mul_qnr(&r, &a);

	/* Compute D@c := (dr+a-d)(dr-ar-d) with a=1 */
	gf_sub(&a, &r, &ONE);
	gf_mulw(&b, &a, EDWARDS_D); /* dr-d */
	gf_add(&a, &b, &ONE);
	gf_sub(&b, &b, &r);
	gf_mul(&c, &a, &b);

	/* compute N := (r+1)(a-2d) */
	gf_add(&a, &r, &ONE);
	gf_mulw(&N, &a, 1 - 2 * EDWARDS_D);

	/* e = +-sqrt(1/ND) or +-r0 * sqrt(qnr/ND) */
	gf_mul(&a, &c, &N);
	mask_t square = gf_isr(&b, &a);
	gf_cond_sel(&c, &r0, &ONE, square); /* r? = square ? 1 : r0 */
	gf_mul(&e, &b, &c);

	/* s@a = +-|N.e| */
	gf_mul(&a, &N, &e);
	gf_cond_neg(&a, gf_lobit(&a) ^ ~square);

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

	/* Reveal the first mask: the sign of s has been decided by the result of gf_isr */
	*psgn_s = ~square;

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

	mask_t succ_rotate_0_altx_1 = gf_eq(&saved_s, &s_rotate_0_altx_1);
	mask_t succ_rotate_1_altx_0 = gf_eq(&saved_s, &s_rotate_1_altx_0);
	mask_t succ_rotate_1_altx_1 = gf_eq(&saved_s, &s_rotate_1_altx_1);

	*psgn_ed_T = succ_rotate_1_altx_0 | succ_rotate_1_altx_1;
	*psgn_altx = succ_rotate_0_altx_1 | succ_rotate_1_altx_1;

	mask_t is_identity = gf_eq(&p->t, &ZERO);

	mask_t sgn_ed_T_if_identity, sgn_altx_if_identity, sgn_s_if_identity;
	mask_t sgn_ed_T_tmp, sgn_altx_tmp, sgn_s_tmp, sgn_tmp;
	char sgn_tmp_short;

	sgn_ed_T_if_identity = 0;
	sgn_altx_if_identity = 0;
	sgn_s_if_identity = 0;

	for (int i = 0; i < 8; i++) {
		if (i == 4) {
			/* skip the 5th one */
			continue;
		}

		sgn_ed_T_tmp = -((i >> 0) & 1);
		sgn_altx_tmp = -((i >> 1) & 1);
		sgn_s_tmp = -((i >> 2) & 1);

		sgn_tmp_short = constant_time_memcmp(ser, ristretto_elgamal_blind_points[i], SER_BYTES);
		sgn_tmp = -(sgn_tmp_short != 0);

		sgn_ed_T_if_identity |= sgn_ed_T_tmp & sgn_tmp;
		sgn_altx_if_identity |= sgn_altx_tmp & sgn_tmp;
		sgn_s_if_identity |= sgn_s_tmp & sgn_tmp;
	}

	sgn_ed_T_if_identity &= is_identity;
	sgn_altx_if_identity &= is_identity;
	sgn_s_if_identity &= is_identity;

	(*psgn_ed_T) &= ~is_identity;
	(*psgn_altx) &= ~is_identity;
	(*psgn_s) &= ~is_identity;

	(*psgn_ed_T) |= sgn_ed_T_if_identity;
	(*psgn_altx) |= sgn_altx_if_identity;
	(*psgn_s) |= sgn_s_if_identity;
}
