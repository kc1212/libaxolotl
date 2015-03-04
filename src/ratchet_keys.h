
#ifndef _ratchet_keys_h
#define _ratchet_keys_h

#include "common.h"

struct ratchet_message_key {
	unsigned char cipher_key[COMMON_KEY_LEN];
	unsigned char mac_key[COMMON_KEY_LEN];
	unsigned char iv[32];
	int counter;
};

#endif


