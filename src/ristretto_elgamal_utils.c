#include <ristretto_elgamal.h>
#include <stdio.h>

uint8_t constant_time_memcmp(const uint8_t *a1, const uint8_t *a2, int len) {
	uint8_t res = 0, tmp;

	for (int i = 0; i < len; i++) {
		tmp = -(a1[i] != a2[i]);
		res = res | tmp;

		/* if a1[i] does not equal a2[i], res is set to 255 immediately */
	}

	/* reverse res 255 <-> 0 */

	/* if return 0, not equal. if return 255, equal */
	return ~res;
}

void ristretto_elgamal_gf_25519_t_printf(const char *msg, const gf_25519_t *v) {
	uint8_t serial[SER_BYTES];
	gf_serialize(serial, v, 1);

	printf("%s: ", msg);
	for (int i = 0; i < SER_BYTES; i++) {
		printf("%02X", serial[i]);
	}
	printf("\n");
}

void ristretto_elgamal_char_printf(const char *msg, const unsigned char ser[SER_BYTES]) {
	printf("%s: ", msg);
	for (int i = 0; i < SER_BYTES; i++) {
		printf("%02X", ser[i]);
	}
	printf("\n");
}

void shift_to_higher_index(char shift, uint8_t *ser_new, uint8_t *ser_old, int len) {
	/* ser_new can be the same as ser_old */

	assert(shift < 8);

	char inv_shift = 8 - shift;
	char mask_inv_shift = (1 << shift) - 1;

	uint8_t tmp_prev = 0, tmp_next = 0;
	for (int i = 0; i < len; i++) {
		tmp_next = (ser_old[i] >> inv_shift) & mask_inv_shift;
		ser_new[i] = ser_old[i] << shift;
		ser_new[i] = ser_new[i] | tmp_prev;
		tmp_prev = tmp_next;
	}
}

void shift_to_lower_index(char shift, uint8_t *ser_new, uint8_t *ser_old, int len) {
	/* ser_new can be the same as ser_old */

	assert(shift < 8);

	char inv_shift = 8 - shift;
	char mask_shift = (1 << shift) - 1;

	uint8_t tmp_prev = 0, tmp_next = 0;
	for (int i = len - 1; i >= 0; i--) {
		tmp_next = ser_old[i] & mask_shift;
		ser_new[i] = ser_old[i] >> shift;
		tmp_prev = tmp_prev << inv_shift;
		ser_new[i] = ser_new[i] | tmp_prev;
		tmp_prev = tmp_next;
	}
}
