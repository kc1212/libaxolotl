
#ifndef _curve_h
#define _curve_h

#include <sodium.h>

struct curve_key_pair {
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
};

int curve_generate_keypair(struct curve_key_pair* pair);

#endif
