
#ifndef _derived_root_secrets_h
#define _derived_root_secrets_h

#define DERIVED_ROOT_SECRETS_SIZE 64

struct derived_root_secrets {
	unsigned char root_key[32];
	unsigned char chain_key[32];
};

int derived_root_secrets_init(struct derived_root_secrets* secrets,
		const unsigned char* in);

#endif


