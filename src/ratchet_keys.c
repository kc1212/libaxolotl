
#include <string.h>
#include <sodium.h>

#include "ratchet_keys.h"
#include "derived_msg_secrets.h"
#include "derived_root_secrets.h"
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
	sodium_memzero(out, sizeof(struct ratchet_chainkey));
	memcpy(out->key, key, COMMON_KEY_LEN);
	out->hkdf = hkdf;
	out->index = index;
	return 0;
}

int ratchet_chainkey_getnext(struct ratchet_chainkey* new, const struct ratchet_chainkey* old)
{
	unsigned char next_key[crypto_auth_hmacsha256_BYTES];
	ratchet_get_base_material(next_key, old, CHAIN_KEY_SEED, sizeof CHAIN_KEY_SEED);
	return ratchet_chainkey_init(new, old->hkdf, next_key, old->index+1);
}

int ratchet_chainkey_getmsgkey(struct ratchet_msgkey* msgkey,
		const struct ratchet_chainkey* chainkey)
{
	unsigned char input_key_material[crypto_auth_hmacsha256_BYTES];
	unsigned char key_material_bytes[DERIVED_MSG_SECRETS_SIZE];
	const unsigned char info[] = "WhisperMessageKeys";
	struct derived_msg_secrets key_material;
	int ret = AXOLOTL_SUCCESS;

	ret = ratchet_get_base_material(input_key_material, chainkey,
			MESSAGE_KEY_SEED, sizeof MESSAGE_KEY_SEED);
	SUCCESS_OR_RETURN(ret);

	// size of info - 1 because we don't need null at the end
	ret = hkdf_derive_secrets_nosalt(key_material_bytes, chainkey->hkdf,
			input_key_material, sizeof input_key_material,
			info, sizeof info - 1, DERIVED_MSG_SECRETS_SIZE);
	SUCCESS_OR_RETURN(ret);

	ret = derived_msg_secrets_init(&key_material, key_material_bytes);
	SUCCESS_OR_RETURN(ret);

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


int ratchet_rootkey_init(struct ratchet_rootkey* out, const enum hkdf_msg_ver_t hkdf,
		const unsigned char* key)
{
	out->hkdf = hkdf;
	memcpy(out->key, key, COMMON_KEY_LEN);
	return 0;
}

int ratchet_rootkey_create_chain(struct ratchet_rootkey_chainkey_pair* out,
		const struct ratchet_rootkey* rootkey,
		const struct curve_pk* their_ratchet_key,
		const struct curve_key_pair* our_ratchet_key)
{
	struct derived_root_secrets derived_root_secrets;
	unsigned char shared_secret[CURVE_KEY_BYTES_LEN];
	unsigned char derived_secret_bytes[DERIVED_ROOT_SECRETS_SIZE];
	const unsigned char info[] = "WhisperRatchet";
	int ret = AXOLOTL_SUCCESS;

	ret = curve_calculate_agreement(shared_secret, their_ratchet_key, &our_ratchet_key->sk);
	SUCCESS_OR_RETURN(ret);

	ret = hkdf_derive_secrets(derived_secret_bytes, rootkey->hkdf,
			shared_secret, sizeof shared_secret,
			rootkey->key,  COMMON_KEY_LEN,
			info,          sizeof info - 1, DERIVED_ROOT_SECRETS_SIZE);
	SUCCESS_OR_RETURN(ret);

	ret = derived_root_secrets_init(&derived_root_secrets, derived_secret_bytes);
	SUCCESS_OR_RETURN(ret);

	ret = ratchet_rootkey_init(&out->rootkey, rootkey->hkdf,
			derived_root_secrets.root_key);
	SUCCESS_OR_RETURN(ret);

	ret = ratchet_chainkey_init(&out->chainkey, rootkey->hkdf,
			derived_root_secrets.chain_key, 0);
	SUCCESS_OR_RETURN(ret);

	return 0;
}




