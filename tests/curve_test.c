
#include <stdio.h>
#include <sodium.h>

#include "minunit.h"
#include "../src/ecc/curve.h"

int tests_run = 0;

static char* test_key_bytes()
{
	mu_assert("wrong ret", 32U == crypto_sign_PUBLICKEYBYTES);
	mu_assert("wrong ret", 2*32U == crypto_sign_SECRETKEYBYTES);
	return 0;
}

static char* test_agreement()
{
	const unsigned char alice_public[]  = {
		0x05, 0x1b, 0xb7, 0x59, 0x66,
		0xf2, 0xe9, 0x3a, 0x36, 0x91,
		0xdf, 0xff, 0x94, 0x2b, 0xb2,
		0xa4, 0x66, 0xa1, 0xc0, 0x8b,
		0x8d, 0x78, 0xca, 0x3f, 0x4d,
		0x6d, 0xf8, 0xb8, 0xbf, 0xa2,
		0xe4, 0xee, 0x28
	};

	const unsigned char alice_private[] = {
		0xc8, 0x06, 0x43, 0x9d, 0xc9,
		0xd2, 0xc4, 0x76, 0xff, 0xed,
		0x8f, 0x25, 0x80, 0xc0, 0x88,
		0x8d, 0x58, 0xab, 0x40, 0x6b,
		0xf7, 0xae, 0x36, 0x98, 0x87,
		0x90, 0x21, 0xb9, 0x6b, 0xb4,
		0xbf, 0x59
	};

	const unsigned char bob_public[] = {
		0x05, 0x65, 0x36, 0x14, 0x99,
		0x3d, 0x2b, 0x15, 0xee, 0x9e,
		0x5f, 0xd3, 0xd8, 0x6c, 0xe7,
		0x19, 0xef, 0x4e, 0xc1, 0xda,
		0xae, 0x18, 0x86, 0xa8, 0x7b,
		0x3f, 0x5f, 0xa9, 0x56, 0x5a,
		0x27, 0xa2, 0x2f
	};

	const unsigned char bob_private[] = {
		0xb0, 0x3b, 0x34, 0xc3, 0x3a,
		0x1c, 0x44, 0xf2, 0x25, 0xb6,
		0x62, 0xd2, 0xbf, 0x48, 0x59,
		0xb8, 0x13, 0x54, 0x11, 0xfa,
		0x7b, 0x03, 0x86, 0xd4, 0x5f,
		0xb7, 0x5d, 0xc5, 0xb9, 0x1b,
		0x44, 0x66
	};

	const unsigned char shared[] = {
		0x32, 0x5f, 0x23, 0x93, 0x28,
		0x94, 0x1c, 0xed, 0x6e, 0x67,
		0x3b, 0x86, 0xba, 0x41, 0x01,
		0x74, 0x48, 0xe9, 0x9b, 0x64,
		0x9a, 0x9c, 0x38, 0x06, 0xc1,
		0xdd, 0x7c, 0xa4, 0xc4, 0x77,
		0xe6, 0x29
	};

	struct curve_pk alice_pk;
	struct curve_sk alice_sk;
	struct curve_pk bob_pk;
	struct curve_sk bob_sk;

	mu_assert("", 0 == curve_decode_point(alice_public, 0, &alice_pk));
	mu_assert("", 0 == curve_decode_private_point(alice_private, sizeof alice_private, &alice_sk));

	mu_assert("", 0 == curve_decode_point(bob_public, 0, &bob_pk));
	mu_assert("", 0 == curve_decode_private_point(bob_private, sizeof bob_private, &bob_sk));

	unsigned char shared_one[crypto_scalarmult_BYTES];
	unsigned char shared_two[crypto_scalarmult_BYTES];

	mu_assert("", sizeof shared == crypto_scalarmult_BYTES); // 32
	mu_assert("", 0 == curve_calculate_agreement(&alice_pk, &bob_sk, shared_one));
	mu_assert("", 0 == curve_calculate_agreement(&bob_pk, &alice_sk, shared_two));

	mu_assert("", 0 == sodium_memcmp(shared, shared_one, crypto_scalarmult_BYTES));
	mu_assert("", 0 == sodium_memcmp(shared, shared_two, crypto_scalarmult_BYTES));

	return 0;
}

static char* all_tests()
{
	mu_run_test(test_key_bytes);
	mu_run_test(test_agreement);
	return 0;
}

int main()
{
	char *result = all_tests();
	if (result != 0) {
		printf("%s\n", result);
	}
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}


