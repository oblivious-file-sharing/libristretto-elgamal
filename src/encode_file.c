#include <ristretto_elgamal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/*
* A user uploads Ristretto encoded points to the server.
*/
size_t ristretto_elgamal_return_point_num(size_t filesize) {
	size_t num_of_58_ciphertext_group = ceil(filesize / 1827.0);

	/*
	* Return 59 Ristretto points.
	*/
	return num_of_58_ciphertext_group * (58 + 1);
}

void ristretto_elgamal_encode(point_t *output, const uint8_t *input, const size_t filesize, const size_t maxfilesize) {
	size_t num_of_58_ciphertext_group = ceil(maxfilesize / 1827.0);

	uint8_t *input_encoding = (uint8_t *) malloc(maxfilesize);
	assert(input_encoding != NULL);

	memcpy(input_encoding, input, filesize);
	input_encoding[filesize] = 1;
	for (size_t t = filesize + 1; t < maxfilesize; t++) {
		input_encoding[t] = 0;
	}

#pragma omp parallel for default(shared)
	for (size_t i = 0; i < num_of_58_ciphertext_group; i++) {
		mask_t sgn_ed_T[58];
		mask_t sgn_altx[58];
		mask_t sgn_s[58];

		uint8_t data[SER_BYTES + 1];
		for (int j = 0; j < 58; j++) {
			size_t begin = i * 1827 * 8 + j * 252;
			size_t end = begin + 252;

			size_t begin_index = begin / 8;
			size_t end_index = end / 8;

			memset(data, 0, SER_BYTES + 1);
			memcpy(data, &input_encoding[begin_index], end_index - begin_index + 1);

			shift_to_lower_index(begin % 8, data, data, SER_BYTES + 1);

			data[SER_BYTES - 1] &= 1 + 2 + 4 + 8;

			shift_to_higher_index(3, data, data, SER_BYTES + 1);
			ristretto_elgamal_encode_single_message(&output[i * 59 + j], data, &sgn_ed_T[j], &sgn_altx[j], &sgn_s[j]);
		}

		uint8_t sgn_map[176];
		memset(sgn_map, 0, sizeof(sgn_map));
		for (int j = 0; j < 58; j++) {
			sgn_map[j] = sgn_ed_T[j] & 1;
			sgn_map[58 + j] = sgn_altx[j] & 1;
			sgn_map[58 + 58 + j] = sgn_s[j] & 1;
		}

		memset(data, 0, SER_BYTES + 1);
		for (int k = 0; k < 22; k++) {
			data[k] = sgn_map[k * 8 + 0] << 0
					  | sgn_map[k * 8 + 1] << 1
					  | sgn_map[k * 8 + 2] << 2
					  | sgn_map[k * 8 + 3] << 3
					  | sgn_map[k * 8 + 4] << 4
					  | sgn_map[k * 8 + 5] << 5
					  | sgn_map[k * 8 + 6] << 6
					  | sgn_map[k * 8 + 7] << 7;
		}

		ristretto_elgamal_encode_single_message_hintless_hashonly(&output[i * 59 + 58], data);
	}

	free(input_encoding);
}
