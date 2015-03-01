
#include <stdio.h>
#include <sodium.h>

#include "minunit.h"
#include "../src/kdf/derived_root_secrets.h"

static char* test_drs()
{
	struct drs_data drs;

	mu_assert("", DRS_SIZE == 64);

	unsigned char in[DRS_SIZE];
	for (unsigned char i = 0; i < DRS_SIZE; i++) {
		in[i] = i;
	}

	drs_init(in, &drs);
	mu_assert("", 0 == sodium_memcmp(drs.root_key, in, 32));
	mu_assert("", 0 == sodium_memcmp(drs.chain_key, in + 32, 32));

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
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}

