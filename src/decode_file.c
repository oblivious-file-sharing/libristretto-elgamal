#include <ristretto_elgamal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
* output must have sufficient space for the maxfilesize.
*/
void ristretto_elgamal_decode(uint8_t *output, const point_t *input, const size_t point_num, size_t *filesize_ret,
							  const size_t maxfilesize) {
	size_t num_of_58_ciphertext_group = point_num / (58 + 1);
	memset(output, 0, maxfilesize);

#pragma omp parallel for default(shared)
	for (size_t i = 0; i < num_of_58_ciphertext_group; i++) {
		uint8_t data[SER_BYTES + 1];
		memset(data, 0, SER_BYTES + 1);
		ristretto_elgamal_decode_single_message_hintless_hashonly(&input[i * 59 + 58], data);

		uint8_t sgn_map[176];
		memset(sgn_map, 0, sizeof(sgn_map));

		for (int k = 0; k < 22; k++) {
			sgn_map[k * 8 + 0] = (data[k] >> 0) & 1;
			sgn_map[k * 8 + 1] = (data[k] >> 1) & 1;
			sgn_map[k * 8 + 2] = (data[k] >> 2) & 1;
			sgn_map[k * 8 + 3] = (data[k] >> 3) & 1;
			sgn_map[k * 8 + 4] = (data[k] >> 4) & 1;
			sgn_map[k * 8 + 5] = (data[k] >> 5) & 1;
			sgn_map[k * 8 + 6] = (data[k] >> 6) & 1;
			sgn_map[k * 8 + 7] = (data[k] >> 7) & 1;
		}

		mask_t sgn_ed_T[58];
		mask_t sgn_altx[58];
		mask_t sgn_s[58];

		for (int j = 0; j < 58; j++) {
			sgn_ed_T[j] = -sgn_map[j];
		}
		for (int j = 0; j < 58; j++) {
			sgn_altx[j] = -sgn_map[58 + j];
		}
		for (int j = 0; j < 58; j++) {
			sgn_s[j] = -sgn_map[58 + 58 + j];
		}

		for (int j = 0; j < 58; j++) {
			memset(data, 0, SER_BYTES + 1);
			ristretto_elgamal_decode_single_message(&input[i * 59 + j], data, sgn_ed_T[j], sgn_altx[j], sgn_s[j]);

			shift_to_lower_index(3, data, data, SER_BYTES + 1);

			size_t begin = i * 1827 * 8 + j * 252;
			size_t end = begin + 252;

			size_t begin_index = begin / 8;
			size_t end_index = end / 8;

			shift_to_higher_index(begin % 8, data, data, SER_BYTES + 1);

			for (size_t k = 0; k < end_index - begin_index + 1; k++) {
				output[begin_index + k] |= data[k];
			}
		}
	}

	size_t filesize_res = 0;
	size_t found_ending = 0;
	for (size_t i = maxfilesize - 1;; i--) {
		size_t change_or_not = -((output[i] == 1) & (found_ending == 0));
		found_ending |= change_or_not;
		change_or_not &= i;
		filesize_res |= change_or_not;

		if (i == 0) break;
	}

	*filesize_ret = filesize_res;
}
