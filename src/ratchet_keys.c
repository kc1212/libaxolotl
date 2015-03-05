
#include <string.h>
#include <sodium.h>

#include "ratchet_keys.h"
#include "derived_msg_secrets.h"
#include "common.h"

static const unsigned char MESSAGE_KEY_SEED[1] = {0x01};
static const unsigned char CHAIN_KEY_SEED[1]   = {0x02};

static int ratchet_get_base_material(unsigned char* base_material,
		const struct ratchet_chainkey* chainkey,
		const unsigned char* seed, const size_t seedlen);

int ratchet_msgkey_init(struct ratchet_msgkey* out,
		const unsigned char* cipher_key, const unsigned char* mac_key,
		const unsigned char* iv, const int counter)
{
	if (out == NULL)
		return AXOLOTL_NULL_POINTER;

	sodium_memzero(out, sizeof(struct ratchet_msgkey));
	memcpy(out->cipher_key, cipher_key, COMMON_KEY_LEN);
	memcpy(out->mac_key, mac_key, COMMON_KEY_LEN);
	memcpy(out->iv, iv, COMMON_IV_LEN);
	out->counter = counter;

	return 0;
}

int ratchet_chainkey_init(struct ratchet_chainkey* out,
		const enum hkdf_msg_ver_t hkdf, const unsigned char* key, const int index)
{
	if (out == NULL)
		return AXOLOTL_NULL_POINTER;

	sodium_memzero(out, sizeof(struct ratchet_chainkey));
	memcpy(out->key, key, COMMON_KEY_LEN);
	out->hkdf = hkdf;
	out->index = index;
	return 0;
}

int ratchet_chainkey_getnext(struct ratchet_chainkey* new, const struct ratchet_chainkey* old)
{
	unsigned char next_key[crypto_auth_hmacsha256_BYTES];
	return ratchet_chainkey_init(new, old->hkdf, next_key, old->index+1);
}

int ratchet_chainkey_getmsgkey(struct ratchet_msgkey* msgkey,
		const struct ratchet_chainkey* chainkey)
{
	unsigned char input_key_material[crypto_auth_hmacsha256_BYTES];
	unsigned char key_material_bytes[DERIVED_MSG_SECRETS_SIZE];
	const unsigned char info[] = "WhisperMessageKeys";
	struct derived_msg_secrets key_material;

	ratchet_get_base_material(input_key_material, chainkey,
			MESSAGE_KEY_SEED, sizeof MESSAGE_KEY_SEED);

	hkdf_derive_secrets_zerosalt(key_material_bytes, chainkey->hkdf,
			input_key_material, sizeof input_key_material,
			info, sizeof info, DERIVED_MSG_SECRETS_SIZE);

	derived_msg_secrets_init(&key_material, key_material_bytes);

	return ratchet_msgkey_init(msgkey, key_material.cipher_key,
			key_material.mac_key, key_material.iv, chainkey->index);
}

// base_material are 32 bytes
static int ratchet_get_base_material(unsigned char* base_material,
		const struct ratchet_chainkey* chainkey,
		const unsigned char* seed, const size_t seedlen)
{
	crypto_auth_hmacsha256_state state;
	crypto_auth_hmacsha256_init(&state, chainkey->key, COMMON_KEY_LEN);
	crypto_auth_hmacsha256_update(&state, seed, seedlen);
	return crypto_auth_hmacsha256_final(&state, base_material);
}


