
#ifndef _curve_h
#define _curve_h

#include "common.h"
#include <stdlib.h>

#define CURVE_KEY_BYTES_LEN COMMON_KEY_LEN
#define CURVE_SIG_BYTES_LEN 64
#define CURVE_PUBLIC_SERIALIZED_LEN (CURVE_KEY_BYTES_LEN + 1)
#define CURVE_SECRET_SERIALIZED_LEN (CURVE_KEY_BYTES_LEN)

// we're using Curve25519 keys

struct curve_pk {
	int type;
	unsigned char bytes[CURVE_KEY_BYTES_LEN];
};

struct curve_sk {
	int type;
	unsigned char bytes[CURVE_KEY_BYTES_LEN];
};

struct curve_key_pair {
	struct curve_pk pk;
	struct curve_sk sk;
};

int curve_generate_keypair(struct curve_key_pair* pair);
int curve_decode_point(struct curve_pk* pk,
		const unsigned char* bytes, const int offset);
int curve_decode_private_point(struct curve_sk* sk,
		const unsigned char* bytes, const size_t byteslen);
int curve_calculate_agreement(unsigned char* out, const struct curve_pk* cpk,
		const struct curve_sk* sk);
int curve_verify_signature(const unsigned char* sig, const struct curve_pk* pk,
		const unsigned char* msg, const size_t msglen);
int curve_calculate_signature(unsigned char* sig, const struct curve_sk* sk,
		const unsigned char* msg, const size_t msglen);
int curve_serialize_pk(unsigned char* out, const struct curve_pk* pk);
int curve_serialize_sk(unsigned char* out, const struct curve_sk* sk);


#endif
