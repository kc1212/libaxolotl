
#ifndef _derived_root_secrets_h
#define _derived_root_secrets_h

#define DRS_SIZE 64

struct drs_data {
	unsigned char root_key[32];
	unsigned char chain_key[32];
};

int drs_init(struct drs_data* drs, const unsigned char* in);

#endif


