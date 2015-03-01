
#include <string.h>

#include "curve.h"
#include "../common/axolotl_errors.h"

#define KEY_BYTES_LEN crypto_sign_PUBLICKEYBYTES

static const int CURVE_DJB_TYPE = 0x05;

int curve_generate_keypair(struct curve_key_pair* pair)
{
	pair->pk.type = CURVE_DJB_TYPE;
	pair->sk.type = CURVE_DJB_TYPE;
	return crypto_sign_keypair(pair->pk.bytes, pair->sk.bytes);
}

int curve_decode_point(const unsigned char* bytes, const int offset,
		struct curve_pk* pk)
{
	int type = bytes[offset] & 0xff;

	if (type == CURVE_DJB_TYPE) {
		sodium_memzero(pk->bytes, crypto_sign_PUBLICKEYBYTES);
		pk->type = CURVE_DJB_TYPE;
		memcpy(pk->bytes, bytes+offset+1, KEY_BYTES_LEN);
		return 0;
	}
	return AXOLOTL_INVALID_KEY;
}

int curve_decode_private_point(const unsigned char* bytes, const size_t byteslen,
		struct curve_sk* sk)
{
	if (byteslen > crypto_sign_SECRETKEYBYTES)
		return -1;

	sodium_memzero(sk->bytes, crypto_sign_SECRETKEYBYTES);
	sk->type = CURVE_DJB_TYPE;
	memcpy(sk->bytes, bytes, byteslen);
	return 0;
}

// out should have length of crypto_scalarmult_BYTES
int curve_calculate_agreement(const struct curve_pk* cpk, const struct curve_sk* csk,
		unsigned char* out)
{
	if (cpk->type != csk->type)
		return AXOLOTL_INVALID_KEY;

	if (cpk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	return crypto_scalarmult(out, csk->bytes, cpk->bytes);
}

// return value of zero means ok
int curve_verify_signature(const struct curve_pk* cpk, const unsigned char* msg,
		const size_t msglen, const unsigned char* sig)
{
	if (cpk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	return crypto_sign_verify_detached(sig, msg, msglen, cpk->bytes);
}

// max siglen is crypto_sign_BYTES
int curve_calculate_signature(const struct curve_sk* csk, const unsigned char* msg,
		const size_t msglen, unsigned char* sig, unsigned long long* siglen)
{
	if (csk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	return crypto_sign_detached(sig, siglen, msg, msglen, csk->bytes);
}



