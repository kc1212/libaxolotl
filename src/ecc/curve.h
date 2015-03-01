
#ifndef _curve_h
#define _curve_h

#include <sodium.h>

struct curve_pk {
	unsigned char bytes[crypto_sign_PUBLICKEYBYTES];
	int type;
};

struct curve_sk {
	unsigned char bytes[crypto_sign_SECRETKEYBYTES];
	int type;
};

struct curve_key_pair {
	struct curve_pk pk;
	struct curve_sk sk;
};

int curve_generate_keypair(struct curve_key_pair* pair);
int curve_decode_point(const unsigned char* bytes, const int offset,
		struct curve_pk* pk);
int curve_decode_private_point(const unsigned char* bytes, const size_t byteslen,
		struct curve_sk* sk);
int curve_calculate_agreement(const struct curve_pk* cpk, const struct curve_sk* csk,
		unsigned char* out);
int curve_verify_signature(const struct curve_pk* cpk, const unsigned char* msg,
		const size_t msglen, const unsigned char* sig);
int curve_calculate_signature(const struct curve_sk* csk, const unsigned char* msg,
		const size_t msglen, unsigned char* sig, unsigned long long* siglen);
#endif
