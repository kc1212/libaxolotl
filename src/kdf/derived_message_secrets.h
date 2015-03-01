
#ifndef _derived_message_secrets_h
#define _derived_message_secrets_h

#define DMS_SIZE 80
#define DMS_CIPHER_KEY_LEN 32
#define DMS_MAC_KEY_LEN 32
#define DMS_IV_LEN 16

struct dms_data {
	unsigned char cipher_key[DMS_CIPHER_KEY_LEN];
	unsigned char mac_key[DMS_MAC_KEY_LEN];
	unsigned char iv[DMS_IV_LEN];
};

int dms_init(unsigned char* in, struct dms_data* dms);

#endif
