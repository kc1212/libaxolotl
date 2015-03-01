
#include <stdio.h>

#include "minunit.h"
#include "../src/kdf/derived_root_secrets.h"

static char* test_drs()
{
	struct drs_data drs;

	mu_assert("", DRS_SIZE == DRS_CIPHER_KEY_LEN + DRS_MAC_KEY_LEN + DRS_IV_LEN);

	unsigned char in[DRS_SIZE];
	for (unsigned char i = 0; i < DRS_SIZE; i++) {
		in[i] = i;
	}

	drs_init(in, &drs);
	mu_assert("", 0 == memcmp(drs.cipher_key, in, DRS_CIPHER_KEY_LEN));
	mu_assert("", 0 == memcmp(drs.mac_key, in + DRS_CIPHER_KEY_LEN, DRS_MAC_KEY_LEN));
	mu_assert("", 0 == memcmp(drs.iv, in + DRS_CIPHER_KEY_LEN + DRS_MAC_KEY_LEN, DRS_IV_LEN));

	return 0;
}

int tests_run = 0;

static char* all_tests()
{
	mu_run_test(test_drs);
	return 0;
}

int main()
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

