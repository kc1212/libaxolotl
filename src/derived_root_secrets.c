
#include <string.h>

#include "derived_root_secrets.h"

int drs_init(struct drs_data* drs, const unsigned char* in)
{
	if (drs == NULL)
		return -1;

	memcpy(drs->root_key, in, 32);
	memcpy(drs->chain_key, in + 32, 32);
	return 0;
}


