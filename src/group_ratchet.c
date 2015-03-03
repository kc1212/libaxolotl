
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "group_ratchet.h"
#include "hkdf.h"
#include "common.h"

static const unsigned char GR_MESSAGE_KEY_SEED[1] = {0x01};
static const unsigned char GR_CHAIN_KEY_SEED[1]   = {0x02};

int gr_sender_message_key_init(const int iteration, const unsigned char* seed,
		const size_t seedlen, struct gr_sender_message_key* msgkey)
{
	const int derivativelen = 48;
	unsigned char derivative[derivativelen];
	const unsigned char info[] = "WhisperGroup";

	if (seedlen > GR_SEED_LEN)
		return AXOLOTL_INVALID_KEYLEN;

	int ret = hkdf_derive_secrets_zerosalt(HKDF_MESSAGE_V3, seed, seedlen,
			info, sizeof info, derivativelen, derivative);
	if (ret != AXOLOTL_SUCCESS)
		return AXOLOTL_CRITICAL_ERROR;

	sodium_memzero(msgkey->seed, seedlen);
	sodium_memzero(msgkey->iv, 16);
	sodium_memzero(msgkey->key, COMMON_KEY_LEN);

	msgkey->iteration = iteration;
	memcpy(msgkey->seed, seed, seedlen);
	memcpy(msgkey->iv, derivative, 16);
	memcpy(msgkey->key, derivative+16, COMMON_KEY_LEN);

	return 0;
}

int gr_sender_chain_key_init(const int iteration, const unsigned char* key,
		struct gr_sender_chain_key* chainkey)
{
	chainkey->iteration = iteration;
	memcpy(chainkey->key, key, COMMON_KEY_LEN);
	return 0;
}

int gr_sender_chain_key_derive(const unsigned char* seed, const size_t seedlen,
		const unsigned char* key, unsigned char* newkey)
{
	return crypto_auth_hmacsha256(newkey, seed, seedlen, key);
}

int gr_sender_chain_key_next(const struct gr_sender_chain_key* old,
		struct gr_sender_chain_key* new)
{
	new->iteration = old->iteration + 1;
	return gr_sender_chain_key_derive(GR_CHAIN_KEY_SEED, 1,
			old->key, new->key);
}

int gr_sender_chain_key_msgkey(const struct gr_sender_chain_key* chainkey,
	struct gr_sender_message_key* msgkey)
{
	unsigned char seed[GR_SEED_LEN];
	gr_sender_chain_key_derive(GR_MESSAGE_KEY_SEED, 1, chainkey->key, seed);
	return gr_sender_message_key_init(chainkey->iteration, seed, GR_SEED_LEN,
			msgkey);
}



