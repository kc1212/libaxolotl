
#ifndef _utils_h
#define _utils_h

#include <stdlib.h>
#include <stdio.h>

void print_hex(const unsigned char* in, const size_t inlen)
{
	for (unsigned i = 0; i < inlen; i++) {
		printf("%02X", in[i] & 0xff);
	}
	printf("\n");
}

#endif

