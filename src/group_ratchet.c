
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "group_ratchet.h"
#include "hkdf.h"
#include "common.h"

static const unsigned char GR_MESSAGE_KEY_SEED[1] = {0x01};
static const unsigned char GR_CHAIN_KEY_SEED[1]   = {0x02};

int gr_sender_message_key_init(struct gr_sender_message_key* msgkey,
		const int iteration, const unsigned char* seed, const size_t seedlen)
{
	const int derivativelen = 48;
	unsigned char derivative[derivativelen];
	const unsigned char info[] = "WhisperGroup";

	if (seedlen > GR_SEED_LEN)
		return AXOLOTL_INVALID_KEYLEN;

	int ret = hkdf_derive_secrets_nosalt(derivative, HKDF_MESSAGE_V3, seed, seedlen,
			info, sizeof info, derivativelen);
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

int gr_sender_chain_key_init(struct gr_sender_chain_key* chainkey,
		const int iteration, const unsigned char* key)
{
	chainkey->iteration = iteration;
	memcpy(chainkey->key, key, COMMON_KEY_LEN);
	return 0;
}

int gr_sender_chain_key_derive(unsigned char* newkey, const unsigned char* seed,
		const size_t seedlen, const unsigned char* key)
{
	return crypto_auth_hmacsha256(newkey, seed, seedlen, key);
}

int gr_sender_chain_key_next(struct gr_sender_chain_key* new,
		const struct gr_sender_chain_key* old)
{
	new->iteration = old->iteration + 1;
	return gr_sender_chain_key_derive(new->key, GR_CHAIN_KEY_SEED, 1, old->key);
}

int gr_sender_chain_key_msgkey(struct gr_sender_message_key* msgkey,
		const struct gr_sender_chain_key* chainkey)
{
	unsigned char seed[GR_SEED_LEN];
	gr_sender_chain_key_derive(seed, GR_MESSAGE_KEY_SEED, 1, chainkey->key);
	return gr_sender_message_key_init(msgkey, chainkey->iteration, seed, GR_SEED_LEN);
}



