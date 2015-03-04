
#include <string.h>
#include <sodium.h>

#include "curve.h"
#include "common.h"
#include "curve_sigs.h" // from ref10

static const int CURVE_DJB_TYPE = 0x05;

int curve_generate_keypair(struct curve_key_pair* pair)
{
	if (pair == NULL)
		return AXOLOTL_NULL_POINTER;

	randombytes_buf(pair->sk.bytes, CURVE_KEY_BYTES_LEN);
	pair->sk.bytes[0] &= 248;
	pair->sk.bytes[31] &= 127;
	pair->sk.bytes[31] |= 64;

	const unsigned char basepoint[CURVE_KEY_BYTES_LEN] = {9};
	crypto_scalarmult_curve25519(pair->pk.bytes, pair->sk.bytes, basepoint);

	pair->pk.type = CURVE_DJB_TYPE;
	pair->sk.type = CURVE_DJB_TYPE;

	return 0;
}

int curve_decode_point(struct curve_pk* pk,
		const unsigned char* bytes, const int offset)
{
	// TODO NULL check
	int type = bytes[offset] & 0xff;

	if (type == CURVE_DJB_TYPE) {
		sodium_memzero(pk->bytes, CURVE_KEY_BYTES_LEN);
		pk->type = CURVE_DJB_TYPE;
		memcpy(pk->bytes, bytes+offset+1, CURVE_KEY_BYTES_LEN);
		return 0;
	}
	return AXOLOTL_INVALID_KEY;
}

int curve_decode_private_point(struct curve_sk* sk,
		const unsigned char* bytes, const size_t byteslen)
{
	if (bytes == NULL || sk == NULL)
		return AXOLOTL_NULL_POINTER;

	if (byteslen > CURVE_KEY_BYTES_LEN)
		return AXOLOTL_INVALID_KEYLEN;

	sodium_memzero(sk->bytes, CURVE_KEY_BYTES_LEN);
	sk->type = CURVE_DJB_TYPE;
	memcpy(sk->bytes, bytes, byteslen);
	return 0;
}

// out should have length of CURVE_KEY_BYTES_LEN
int curve_calculate_agreement(unsigned char* out, const struct curve_pk* pk,
		const struct curve_sk* sk)
{
	if (pk->type != sk->type)
		return AXOLOTL_INVALID_KEY;

	if (pk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	return crypto_scalarmult_curve25519(out, sk->bytes, pk->bytes);
}

// return value of zero means ok
int curve_verify_signature(const unsigned char* sig, const struct curve_pk* pk,
		const unsigned char* msg, const size_t msglen)
{
	if (pk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	return curve25519_verify(sig, pk->bytes, msg, msglen);
}

// max siglen is CURVE_KEY_BYTES_LEN
int curve_calculate_signature(unsigned char* sig, const struct curve_sk* sk,
		const unsigned char* msg, const size_t msglen)
{
	if (sk->type != CURVE_DJB_TYPE)
		return AXOLOTL_INVALID_KEY;

	unsigned char random[64];
	randombytes_buf(random, sizeof random);
	return curve25519_sign(sig, sk->bytes, msg, msglen, random);
}

// out must have at least length of 33, or CURVE_KEY_BYTES_LEN + 1
int curve_serialize_pk(unsigned char* out, const struct curve_pk* pk)
{
	if (pk == NULL || out == NULL)
		return AXOLOTL_NULL_POINTER;

	out[0] = (unsigned char) pk->type;
	memcpy(out+1, pk->bytes, CURVE_KEY_BYTES_LEN);
	return 0;
}

// out must have at least CURVE_KEY_BYTES_LEN
int curve_serialize_sk(unsigned char* out, const struct curve_sk* sk)
{
	if (sk == NULL || out == NULL)
		return AXOLOTL_NULL_POINTER;

	memcpy(out, sk->bytes, CURVE_KEY_BYTES_LEN);
	return 0;
}


