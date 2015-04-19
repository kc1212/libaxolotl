
#ifndef _identity_keys_h
#define _identity_keys_h

#include "curve.h"

struct identity_key {
	struct curve_pk pk;
};

struct identity_key_pair {
	// TODO
};

int identify_key_init(struct curve_pk* pk, const unsigned char* bytes, const int offset);
int identity_key_serialize(unsigned char* out, const struct identity_key* ik);
int identity_key_fingerprint(unsigned char* out, const struct identity_key* ik);

#endif


