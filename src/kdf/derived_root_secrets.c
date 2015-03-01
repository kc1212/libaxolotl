
#include <stdlib.h>
#include <string.h>

#include "derived_root_secrets.h"

int drs_init(unsigned char* in, struct drs_data* drs)
{
	if (drs == NULL)
		return -1;

	memcpy(drs->cipher_key, in, DRS_CIPHER_KEY_LEN);
	memcpy(drs->mac_key, in + DRS_CIPHER_KEY_LEN, DRS_MAC_KEY_LEN);
	memcpy(drs->iv, in + DRS_CIPHER_KEY_LEN + DRS_MAC_KEY_LEN, DRS_IV_LEN);
	return 0;
}


