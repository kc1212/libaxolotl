
#include <string.h>

#include "derived_root_secrets.h"

int derived_root_secrets_init(struct derived_root_secrets* secrets,
		const unsigned char* in)
{
	if (secrets == NULL)
		return -1;

	memcpy(secrets->root_key, in, 32);
	memcpy(secrets->chain_key, in + 32, 32);
	return 0;
}


