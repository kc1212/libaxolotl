
#ifndef _derived_root_secrets_h
#define _derived_root_secrets_h

#define DRS_SIZE 80
#define DRS_CIPHER_KEY_LEN 32
#define DRS_MAC_KEY_LEN 32
#define DRS_IV_LEN 16

struct drs_data {
	unsigned char cipher_key[DRS_CIPHER_KEY_LEN];
	unsigned char mac_key[DRS_MAC_KEY_LEN];
	unsigned char iv[DRS_IV_LEN];
};

int drs_init(unsigned char* in, struct drs_data* drs);

#endif


