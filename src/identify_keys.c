
#include "identify_keys.h"

int identity_key_init(struct identity_key* ik, const unsigned char* bytes, const int offset)
{
	return curve_decode_point(&ik->pk, bytes, offset);
}

int identity_key_serialize(unsigned char* out, const struct identity_key* ik)
{
	return curve_serialize_pk(out, &ik->pk);
}

// TODO unimplemented
int identity_key_fingerprint(unsigned char* out, const struct identity_key* ik)
{
	return 0;
}


