
#include <sodium.h>
#include <math.h>
#include <string.h>
#include <stdio.h>

#include "hkdf.h"
#include "common.h"

static const int HASH_OUTSZ = 32;

static int hkdf_extract(unsigned char* out, const unsigned char* salt,
		const size_t saltlen, const unsigned char* in, const size_t inlen);

static int hkdf_expand(unsigned char* out, enum hkdf_msg_ver_t offset,
		const unsigned char* prk, const size_t prklen,
		const unsigned char* info, const size_t infolen,
		const unsigned outlen);

int hkdf_derive_secrets_nosalt(unsigned char* out, enum hkdf_msg_ver_t offset,
		const unsigned char* in, const size_t inlen,
		const unsigned char* info, const size_t infolen,
		const unsigned outlen)
{
	unsigned char salt[HASH_OUTSZ];
	sodium_memzero(salt, sizeof salt);
	return hkdf_derive_secrets(out, offset, in, inlen, salt, sizeof salt, info, infolen, outlen);
}

int hkdf_derive_secrets(unsigned char* out, enum hkdf_msg_ver_t offset,
		const unsigned char* in, const size_t inlen,
		const unsigned char* salt, const size_t saltlen,
		const unsigned char* info, const size_t infolen,
		const unsigned outlen)
{
	unsigned char prk[crypto_auth_hmacsha256_BYTES];
	hkdf_extract(prk, salt, saltlen, in, inlen);
	return hkdf_expand(out, offset, prk, sizeof prk, info, infolen, outlen);
}

static int hkdf_extract(unsigned char* out, const unsigned char* salt, const size_t saltlen,
		const unsigned char* in, const size_t inlen)
{
	crypto_auth_hmacsha256_state state;
	crypto_auth_hmacsha256_init(&state, salt, saltlen);
	crypto_auth_hmacsha256_update(&state, in, inlen);
	return crypto_auth_hmacsha256_final(&state, out);
}

static int hkdf_expand(unsigned char* out, enum hkdf_msg_ver_t offset,
		const unsigned char* prk, const size_t prklen,
		const unsigned char* info, const size_t infolen,
		const unsigned outlen)
{
	unsigned iters = (unsigned) ceil( (double)outlen / (double)HASH_OUTSZ );
	unsigned char mixin[crypto_auth_hmacsha256_BYTES];
	unsigned remaining_bytes = outlen;

	sodium_memzero(out, outlen);
	sodium_memzero(mixin, sizeof mixin);

	unsigned char* tmp_res = out;
	for (unsigned i = offset; i < iters + offset; i++){

		crypto_auth_hmacsha256_state state;
		crypto_auth_hmacsha256_init(&state, prk, prklen);

		if (i != offset)
			crypto_auth_hmacsha256_update(&state, mixin, sizeof mixin);
		if (info != NULL)
			crypto_auth_hmacsha256_update(&state, info, infolen);

		unsigned char ii = (unsigned char)i;
		crypto_auth_hmacsha256_update(&state, &ii, sizeof ii);

		unsigned char step_out[crypto_auth_hmacsha256_BYTES];
		crypto_auth_hmacsha256_final(&state, step_out);

		int steplen = min(remaining_bytes, sizeof step_out);
		memcpy(tmp_res, step_out, steplen);
		tmp_res += steplen;

		memcpy(mixin, step_out, sizeof step_out);
		remaining_bytes -= steplen;
	}

	return 0;
}


