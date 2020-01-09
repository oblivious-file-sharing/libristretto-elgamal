#include <ristretto_elgamal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "word.h"
#include "field.h"

extern const int RISTRETTO255_EDWARDS_D;
extern const gf_25519_t RISTRETTO255_FACTOR;
#define TWISTED_D (-(RISTRETTO255_EDWARDS_D))
#define EDWARDS_D RISTRETTO255_EDWARDS_D

void ristretto_elgamal_encode_single_message_hintless_hashonly(
		point_t *p,
		const uint8_t ser[SER_BYTES]
) {
	/*
	* Store the first 174 bits of the ser.
	*/

	/* Check if the last 10 bytes are clean (the 23rd-32nd bytes - indexed by 22-31) */
	for (int i = 22; i < SER_BYTES; i++) {
		assert(ser[i] == 0);
	}

	/* Check if the higher 2 bits of the 22nd bytes (indexed by 21) are clean */
	assert((ser[21] & 192) == 0);

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256_handle;
	SHA256_Init(&sha256_handle);
	SHA256_Update(&sha256_handle, ser, 22);
	SHA256_Final(hash, &sha256_handle);

	uint8_t newser[SER_BYTES];
	memset(newser, 0, SER_BYTES);
	memcpy(&newser[0], hash, 10);

	/*
	* Copy the first 22 bytes of ser to be starting from the 11th byte of newser.
	*/
	memcpy(&newser[10], ser, 22);

	shift_to_higher_index(1, newser, newser, SER_BYTES);

	// ristretto_elgamal_char_printf("data_to_be_embedded", newser);

	/* Computer r = i * r0 ^ 2
	** To ensure that we can have one r0, the caller needs to set r0 to be positive (not negative),
	** such that r0 is the positive square root of r / i.
	*/
	gf_25519_t r0, r, a, b, c, N, e;
	const uint8_t mask = (uint8_t)(0xFE << (6));
	ignore_result(gf_deserialize(&r0, newser, 0, mask));
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
}
