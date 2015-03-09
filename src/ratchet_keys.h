
#ifndef _ratchet_keys_h
#define _ratchet_keys_h

#include "common.h"
#include "hkdf.h"
#include "curve.h"

struct ratchet_msgkey {
	unsigned char cipher_key[COMMON_KEY_LEN];
	unsigned char mac_key[COMMON_KEY_LEN];
	unsigned char iv[COMMON_IV_LEN];
	int counter;
};

struct ratchet_chainkey {
	unsigned char key[COMMON_KEY_LEN];
	enum hkdf_msg_ver_t hkdf;
	int index;
};

struct ratchet_rootkey {
	unsigned char key[COMMON_KEY_LEN];
	enum hkdf_msg_ver_t hkdf;
};

struct ratchet_rootkey_chainkey_pair {
	struct ratchet_rootkey rootkey;
	struct ratchet_chainkey chainkey;
};

int ratchet_msgkey_init(struct ratchet_msgkey* out,
		const unsigned char* cipher_key, const unsigned char* mac_key,
		const unsigned char* iv, const int counter);

int ratchet_chainkey_init(struct ratchet_chainkey* out,
		const enum hkdf_msg_ver_t hkdf, const unsigned char* key, const int index);

int ratchet_chainkey_getnext(struct ratchet_chainkey* new, const struct ratchet_chainkey* old);

int ratchet_chainkey_getmsgkey(struct ratchet_msgkey* msgkey,
		const struct ratchet_chainkey* chainkey);

int ratchet_rootkey_init(struct ratchet_rootkey* out, const enum hkdf_msg_ver_t hkdf,
		const unsigned char* key);

int ratchet_rootkey_create_chain(struct ratchet_rootkey_chainkey_pair* out,
		const struct ratchet_rootkey* rootkey,
		const struct curve_pk* their_ratchet_key,
		const struct curve_key_pair* our_ratchet_key);
#endif


