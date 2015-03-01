
#ifndef _curve_h
#define _curve_h

#include <sodium.h>

#define CURVE_PUBLIC_SERIALIZEDLEN (crypto_scalarmult_curve25519_BYTES + 1)
#define CURVE_SECRET_SERIALIZEDLEN (crypto_scalarmult_curve25519_BYTES)

struct curve_pk {
	int type;
	unsigned char bytes[crypto_scalarmult_curve25519_BYTES];
};

struct curve_sk {
	int type;
	unsigned char bytes[crypto_scalarmult_curve25519_BYTES];
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
int curve_serialize_pk(const struct curve_pk* pk, unsigned char* out);
int curve_serialize_sk(const struct curve_sk* sk, unsigned char* out);


#endif
