
#include "common.h"
#define GR_SEED_LEN 32

struct gr_sender_message_key {
	int iteration;
	unsigned char iv[16];
	unsigned char key[COMMON_KEY_LEN];
	unsigned char seed[GR_SEED_LEN];
};

struct gr_sender_chain_key {
	int iteration;
	unsigned char key[COMMON_KEY_LEN];
};

int gr_sender_message_key_init(struct gr_sender_message_key* msgkey,
		const int iteration, const unsigned char* seed, const size_t seedlen);


int gr_sender_chain_key_init(struct gr_sender_chain_key* chainkey,
		const int iteration, const unsigned char* key);

int gr_sender_chain_key_derive(unsigned char* newkey, const unsigned char* seed,
		const size_t seedlen, const unsigned char* key);

int gr_sender_chain_key_next(struct gr_sender_chain_key* new,
		const struct gr_sender_chain_key* old);

int gr_sender_chain_key_msgkey(struct gr_sender_message_key* msgkey,
		const struct gr_sender_chain_key* chainkey);
