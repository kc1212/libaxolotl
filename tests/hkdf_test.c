/* file minunit_example.c */

#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "minunit.h"
#include "../src/kdf/hkdf.h"

int tests_run = 0;

static void print_hex(const unsigned char* in, const size_t inlen)
{
	for (unsigned i = 0; i < inlen; i++) {
		printf("%02X", in[i] & 0xff);
	}
	printf("\n");
}

static char* test_vector_v3()
{
	const unsigned char ikm[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b
	};

	const unsigned char salt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c
	};

	const unsigned char info[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
		0xf5, 0xf6, 0xf7, 0xf8, 0xf9
	};

	const unsigned char okm[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa,
		0xac, 0xd5, 0x7a, 0x90, 0x43,
		0x4f, 0x64, 0xd0, 0x36, 0x2f,
		0x2a, 0x2d, 0x2d, 0x0a, 0x90,
		0xcf, 0x1a, 0x5a, 0x4c, 0x5d,
		0xb0, 0x2d, 0x56, 0xec, 0xc4,
		0xc5, 0xbf, 0x34, 0x00, 0x72,
		0x08, 0xd5, 0xb8, 0x87, 0x18,
		0x58, 0x65
	};

	const size_t outlen = 42;
	unsigned char out[outlen];
	memset(out, 0, outlen);

	int ret = hkdf_create_for(3);
	mu_assert("wrong ret", 0 == ret);

	ret = hkdf_derive_secrets(ikm, sizeof ikm, salt, sizeof salt, info, sizeof info, outlen, out);
	mu_assert("wrong ret", 0 == ret);
	mu_assert("wrong output", 0 == sodium_memcmp(out, okm, outlen));
	return 0;
}

static char * all_tests() {
	mu_run_test(test_vector_v3);
	return 0;
}

int main(int argc, char **argv)
{
	char *result = all_tests();
	if (result != 0) {
		printf("%s\n", result);
	}
	else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}



