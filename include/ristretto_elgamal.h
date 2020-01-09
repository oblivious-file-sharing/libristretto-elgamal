#ifndef __RISTRETTO_ELGAMAL__
#define __RISTRETTO_ELGAMAL__

#include <ristretto255.h>
#include "word.h"
#include "field.h"

#include <omp.h>
#include <openssl/sha.h>
#include <stdio.h>

#define scalar_t ristretto255_scalar_t
#define point_t ristretto255_point_t

#ifdef __cplusplus
extern "C" {
#endif

void ristretto_elgamal_gcrypt_init();

void ristretto_elgamal_crypto_random_make_bytes(unsigned char *ret, unsigned int l);

uint8_t constant_time_memcmp(const uint8_t *a1, const uint8_t *a2, int len);

size_t ristretto_elgamal_return_point_num(size_t filesize);

void ristretto_elgamal_encode(point_t *output, const uint8_t *input, const size_t filesize, const size_t maxfilesize);

void ristretto_elgamal_decode(uint8_t *output, const point_t *input, const size_t point_num, size_t *filesize_ret,
							  const size_t maxfilesize);

void ristretto_elgamal_encode_single_message(
		point_t *p,
		const unsigned char ser[SER_BYTES],
		mask_t *sgn_ed_T,
		mask_t *sgn_altx,
		mask_t *sgn_s
);

void ristretto_elgamal_decode_single_message(
		const point_t *p,
		unsigned char ser[SER_BYTES],
		mask_t sgn_ed_T,
		mask_t sgn_altx,
		mask_t sgn_s
);

void ristretto_elgamal_encode_single_message_hintless_hashonly(
		point_t *p,
		const uint8_t ser[SER_BYTES]
);

void ristretto_elgamal_decode_single_message_hintless_hashonly(
		const point_t *p,
		unsigned char ser[SER_BYTES]
);

void ristretto_elgamal_gf_25519_t_printf(const char *msg, const gf_25519_t *v);

void ristretto_elgamal_char_printf(const char *msg, const unsigned char ser[SER_BYTES]);

void shift_to_higher_index(char shift, uint8_t *ser_new, uint8_t *ser_old, int len);

void shift_to_lower_index(char shift, uint8_t *ser_new, uint8_t *ser_old, int len);

static const uint8_t ristretto_elgamal_blind_points[8][SER_BYTES] = {
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\xE7\x73\xA4\xB6\x62\x79\xF5\x8D\x34\x56\x59\x86\x6E\x16\xC1\xDF\xC1\xF8\x0D\x31\x35\x3C\xA0\x08\x74\x5D\x79\xB6\xF5\x62\x9B\x00",
		"\xA8\x1B\x5C\x4A\xCB\x2A\x30\x75\xAA\x6D\xEA\x0E\x2D\xA9\xBC\xCD\x15\x6E\xEB\x73\x99\x54\x34\x75\x97\xEB\x7B\xF4\x58\x55\xB3\x05",
		"\xA2\xCE\x30\x11\xA7\x8E\xF5\x73\x09\x8D\xFF\xFA\x7C\x63\x19\xA2\x97\x31\x84\xA2\x3F\x8C\x7E\x4F\xB2\x8A\x95\xAB\xEE\x32\x61\x5F",
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\xBC\xED\x0D\x08\xAB\x13\x99\x4B\x90\x1F\x93\x9D\x3D\x6F\x16\x4D\x7D\x1F\x1B\x78\x60\xD5\xCC\xDB\xCA\x27\xC4\xB7\x05\xF2\x3D\x02",
		"\x40\x25\x6A\xC5\xE4\xC7\x3A\xF6\x05\x7C\x6D\x51\x20\xF9\x0C\x43\x62\xAB\x4A\xD9\x01\x5B\xC3\x65\x59\x8D\xAC\xA0\x48\xBA\xC4\x00",
		"\x2A\x63\x82\xD9\x8D\x9B\x4F\xE0\x52\x6B\xF3\x2F\x2E\x36\xB1\xC6\xFB\x59\x4E\xDA\xAD\xAA\x30\xF3\x5A\x29\x56\x6C\x59\xAD\xFE\x4C"
};

typedef struct {
	int exp_len;
	int group_slice_len;
	int num_group;
	int group_size;
	ristretto255_point_t (*precompute_table);
} fastecexp_state;

void KeyGen(
		const char *filename_priv_1_key,
		const char *filename_priv_2_key,
		const char *filename_pub_1_key,
		const char *filename_pub_2_key,
		const char *filename_pub_key
);

void KeyGen_stage1(
		const char *filename_priv_srv_key,
		const char *filename_pub_srv_key
);

void KeyGen_stage2(
		const char *filename_pub_1_key,
		const char *filename_pub_2_key,
		const char *filename_pub_key
);

void TablesGen(
		const char *filename_pub_1_key,
		const char *filename_pub_2_key,
		const char *filename_pub_key,
		const char *filename_pub_1_table_format,
		const char *filename_pub_2_table_format,
		const char *filename_pub_table_format
);

void LoadPrivKey(ristretto255_scalar_t *psk, const char *filename_priv_key);

void LoadPubKey(ristretto255_point_t *ppk, const char *filename_pub_key);

void Encrypt(ristretto255_point_t ct[60], const ristretto255_point_t pt[59], const fastecexp_state st_pk[60],
			 FILE *rand_src);

void
Rerand(ristretto255_point_t ct2[60], ristretto255_point_t ct1[60], const fastecexp_state st_pk[60], FILE *rand_src);

void Decrypt(ristretto255_point_t pt[59], ristretto255_point_t ct[60], const ristretto255_scalar_t sk[59]);

void PartDec1(ristretto255_point_t ct_short[1], ristretto255_point_t ct[60]);

void PartDec2(ristretto255_point_t pt[59], ristretto255_point_t ct_short[1], const ristretto255_scalar_t sk[59]);

void PartDec3(ristretto255_point_t ct_dest[59], ristretto255_point_t ct_src[59]);

void Rerand_to_cache(ristretto255_point_t ct[60], const fastecexp_state st_pk[60], FILE *rand_src);

void Rerand_use_cache(ristretto255_point_t ct[60], ristretto255_point_t cache[60]);

void AdjustWindow(const int new_window_size);

void
fastecexp_prepare(const ristretto255_point_t *base, const int exp_len, const int group_slice_len, fastecexp_state *st);

void fastecexp_export_table(const fastecexp_state *st, const char *filename);

void fastecexp_prepare_with_import_table(const int exp_len, const int group_slice_len, fastecexp_state *st,
										 const char *filename);

void fastecexp_compute(ristretto255_point_t *result, const unsigned char *exp, const fastecexp_state *st);

void fastecexp_release(fastecexp_state *st);

void TableGen(const ristretto255_point_t *base, const char *filename);

void TableLoad(fastecexp_state *pst, const char *filename);

void TableRelease(fastecexp_state *pst);

void TableCompute(const fastecexp_state *pst, ristretto255_point_t *p, unsigned char *exp);

size_t Serialize_Honest_Size(int num_of_points);

void Serialize_Honest(unsigned char *out, ristretto255_point_t *in, int num_of_points);

size_t Serialize_Honest_Size_old(int num_of_points);

void Serialize_Honest_old(unsigned char *out, ristretto255_point_t *in, int num_of_points);

size_t Serialize_Malicious_Size(int num_of_points);

void Serialize_Malicious(unsigned char *out, ristretto255_point_t *in, int num_of_points);

void Deserialize_Honest(ristretto255_point_t *out, unsigned char *in, int num_of_points);

void Deserialize_Honest_old(ristretto255_point_t *out, unsigned char *in, int num_of_points);

ristretto_error_t Deserialize_Malicious(ristretto255_point_t *out, unsigned char *in, int num_of_points);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
