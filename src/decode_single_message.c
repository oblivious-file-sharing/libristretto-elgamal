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

void ristretto_elgamal_decode_single_message(
		const point_t *p,
		unsigned char ser[SER_BYTES],
		mask_t sgn_ed_T,
		mask_t sgn_altx,
		mask_t sgn_s
) {
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

	mask_t rotate = gf_lobit(&t3) ^sgn_ed_T;
	gf_cond_swap(&t1, &t2, rotate);
	gf_mul_i(&t4, &p->x);
	gf_cond_sel(&t4, &p->y, &t4, rotate);

	gf_mul_i(&t5, &RISTRETTO255_FACTOR);  /* t5 = imi */
	gf_mul(&t3, &t5, &t2);
	gf_mul(&t2, &t5, &t1);
	gf_mul(&t5, &t2, &p->t);

	mask_t negx = gf_lobit(&t5) ^sgn_altx;

	gf_cond_neg(&t1, rotate ^ negx);
	gf_mul(&t2, &t1, &p->z);
	gf_add(&t2, &t2, &ONE);

	gf_25519_t inv_el_sum;
	gf_mul(&inv_el_sum, &t2, &t4);

	gf_25519_t s;
	gf_mul(&s, &inv_el_sum, &t3);

	mask_t negs = gf_lobit(&s);
	gf_cond_neg(&s, negs ^ sgn_s);

	mask_t negz = (~negs) ^sgn_s ^negx;

	gf_25519_t inv_el_m1;
	gf_copy(&inv_el_m1, &p->z);
	gf_cond_neg(&inv_el_m1, negz);
	gf_sub(&inv_el_m1, &inv_el_m1, &t4);

	gf_25519_t a, b, c;
	gf_copy(&b, &inv_el_sum);
	gf_copy(&c, &inv_el_m1);

	mask_t is_identity = gf_eq(&p->t, &ZERO);

	/* Terrible, terrible special casing due to lots of 0/0 is deisogenize
	* Basically we need to generate -D and +- i*RISTRETTO255_FACTOR
	*/
	gf_mul_i(&a, &RISTRETTO255_FACTOR);
	gf_cond_sel(&b, &b, &ONE, is_identity);
	gf_cond_neg(&a, sgn_altx);
	gf_cond_sel(&c, &c, &a, is_identity & sgn_ed_T);
	gf_cond_sel(&c, &c, &ZERO, is_identity & ~sgn_ed_T);
	gf_mulw(&a, &ONE, -EDWARDS_D);
	gf_cond_sel(&c, &c, &a, is_identity & ~sgn_ed_T & ~sgn_altx);

	gf_mulw(&a, &b, -EDWARDS_D);
	gf_add(&b, &a, &b);
	gf_sub(&a, &a, &c);
	gf_add(&b, &b, &c);
	gf_cond_swap(&a, &b, sgn_s);
	gf_mul_qnr(&c, &b);
	gf_mul(&b, &c, &a);

	mask_t succ = gf_isr(&c, &b);
	succ |= gf_eq(&b, &ZERO);
	gf_mul(&b, &c, &a);
	gf_cond_neg(&b, gf_lobit(&b));

	gf_serialize(ser, &b, 1);
	/*
	* Input requirement:
	* At least ser[0]'s lowest bit is 0 and ser[SER_BYTES - 1]'s highest bit is 0.
	*/
	assert((ser[0] & 1) == 0);
	assert((ser[SER_BYTES - 1] & 128) == 0);
}
