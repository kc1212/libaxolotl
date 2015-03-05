
#include <string.h>
#include "derived_msg_secrets.h"

int derived_msg_secrets_init(struct derived_msg_secrets* derived_msg_secrets,
		const unsigned char* in)
{
	if (derived_msg_secrets == NULL)
		return -1;

	memcpy(derived_msg_secrets->cipher_key,
			in, DERIVED_MSG_SECRETS_CIPHER_KEY_LEN);
	memcpy(derived_msg_secrets->mac_key,
			in + DERIVED_MSG_SECRETS_CIPHER_KEY_LEN, DERIVED_MSG_SECRETS_MAC_KEY_LEN);
	memcpy(derived_msg_secrets->iv,
			in + DERIVED_MSG_SECRETS_CIPHER_KEY_LEN + DERIVED_MSG_SECRETS_MAC_KEY_LEN,
			DERIVED_MSG_SECRETS_IV_LEN);
	return 0;
}

