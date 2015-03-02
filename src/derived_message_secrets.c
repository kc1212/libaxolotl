
#include <string.h>
#include "derived_message_secrets.h"

int dms_init(unsigned char* in, struct dms_data* dms)
{
	if (dms == NULL)
		return -1;

	memcpy(dms->cipher_key, in, DMS_CIPHER_KEY_LEN);
	memcpy(dms->mac_key, in + DMS_CIPHER_KEY_LEN, DMS_MAC_KEY_LEN);
	memcpy(dms->iv, in + DMS_CIPHER_KEY_LEN + DMS_MAC_KEY_LEN, DMS_IV_LEN);
	return 0;
}

