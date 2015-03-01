
#include <string.h>

#include "curve.h"
#include "../common/axolotl_errors.h"

#define KEY_BYTES_LEN crypto_scalarmult_curve25519_BYTES

static const int CURVE_DJB_TYPE = 0x05;

int curve_generate_keypair(struct curve_key_pair* pair)
{
	unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];

	crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);
	crypto_sign_ed25519_pk_to_curve25519(pair->pk.bytes, ed25519_pk);
	crypto_sign_ed25519_sk_to_curve25519(pair->sk.bytes, ed25519_skpk);

	pair->pk.type = CURVE_DJB_TYPE;
	pair->sk.type = CURVE_DJB_TYPE;

	sodium_memzero(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES);
	sodium_memzero(ed25519_skpk, crypto_sign_ed25519_SECRETKEYBYTES);
	return 0;
}

int curve_decode_point(const unsigned char* bytes, const int offset,
		struct curve_pk* pk)
{
	int type = bytes[offset] & 0xff;

	if (type == CURVE_DJB_TYPE) {
		sodium_memzero(pk->bytes, crypto_scalarmult_curve25519_BYTES);
		pk->type = CURVE_DJB_TYPE;
		memcpy(pk->bytes, bytes+offset+1, KEY_BYTES_LEN);
		return 0;
	}
	return AXOLOTL_INVALID_KEY;
}

int curve_decode_private_point(const unsigned char* bytes, const size_t byteslen,
		struct curve_sk* sk)
{
	// TODO  check for null
	if (byteslen > crypto_scalarmult_curve25519_BYTES)
		return AXOLOTL_INVALID_KEYLEN;

	sodium_memzero(sk->bytes, crypto_scalarmult_curve25519_BYTES);
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

	return crypto_scalarmult_curve25519(out, csk->bytes, cpk->bytes);
}

// return value of zero means ok
int curve_verify_signature(const struct curve_pk* cpk, const unsigned char* msg,
		const size_t msglen, const unsigned char* sig)
{
	if (cpk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	// TODO this functions uses Ed25519 keys, need to convert our keys
	return crypto_sign_verify_detached(sig, msg, msglen, cpk->bytes);
}

// max siglen is crypto_sign_BYTES
int curve_calculate_signature(const struct curve_sk* csk, const unsigned char* msg,
		const size_t msglen, unsigned char* sig, unsigned long long* siglen)
{
	if (csk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	// TODO this functions uses Ed25519 keys, need to convert our keys
	return crypto_sign_detached(sig, siglen, msg, msglen, csk->bytes);
}

// out must have at least length of 33, or crypto_scalarmult_curve25519_BYTES + 1
int curve_serialize_pk(const struct curve_pk* pk, unsigned char* out)
{
	if (pk == NULL || out == NULL)
		return AXOLOTL_NULL_POINTER;

	out[0] = (unsigned char) pk->type;
	memcpy(out+1, pk->bytes, crypto_scalarmult_curve25519_BYTES);
	return 0;
}

// out must have at least length of 64 or crypto_scalarmult_curve25519_BYTES
int curve_serialize_sk(const struct curve_sk* sk, unsigned char* out)
{
	if (sk == NULL || out == NULL)
		return AXOLOTL_NULL_POINTER;

	memcpy(out, sk->bytes, crypto_scalarmult_curve25519_BYTES);
	return 0;
}


