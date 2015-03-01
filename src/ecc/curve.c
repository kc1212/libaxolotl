
#include <string.h>
#include "curve.h"

static const int DJB_TYPE = 0x05;
static const int key_bytes_len = 32;

int curve_generate_keypair(struct curve_key_pair* pair)
{
	return crypto_sign_keypair(pair->pk, pair->sk);
}

int curve_decode_point(const unsigned char* bytes, const int offset,
		unsigned char* key_bytes)
{
	int type = bytes[offset] & 0xff;

	if (type == DJB_TYPE) {
		memcpy(key_bytes, bytes+offset+1, key_bytes_len);
		return 0;
	}
	return -1;
}

int curve_decode_private_point()
{
	return 0;
}

int curve_calculate_agreement()
{
	return 0;
}

int curve_verify_signature()
{
	return 0;
}

int curve_calculate_signature()
{
	return 0;
}


