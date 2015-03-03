
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

int gr_sender_message_key_init(const int iteration, const unsigned char* seed,
		const size_t seedlen, struct gr_sender_message_key* senderkey);


int gr_sender_chain_key_init(const int iteration, const unsigned char* key,
		struct gr_sender_chain_key* chainkey);

int gr_sender_chain_key_derive(const unsigned char* seed, const size_t seedlen,
		const unsigned char* key, unsigned char* newkey);

int gr_sender_chain_key_next(const struct gr_sender_chain_key* old,
		struct gr_sender_chain_key* new);

int gr_sender_chain_key_msgkey(const struct gr_sender_chain_key* chainkey,
	struct gr_sender_message_key* msgkey);


