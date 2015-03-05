
#ifndef _derived_message_secrets_h
#define _derived_message_secrets_h

#define DERIVED_MSG_SECRETS_SIZE 80
#define DERIVED_MSG_SECRETS_CIPHER_KEY_LEN 32
#define DERIVED_MSG_SECRETS_MAC_KEY_LEN 32
#define DERIVED_MSG_SECRETS_IV_LEN 16

struct derived_msg_secrets {
	unsigned char cipher_key[DERIVED_MSG_SECRETS_CIPHER_KEY_LEN];
	unsigned char mac_key[DERIVED_MSG_SECRETS_MAC_KEY_LEN];
	unsigned char iv[DERIVED_MSG_SECRETS_IV_LEN];
};

int derived_msg_secrets_init(struct derived_msg_secrets* derived_msg_secrets,
		const unsigned char* in);

#endif
