
#include <stdio.h>
#include <string.h>

#include "minunit.h"
#include "../src/derived_root_secrets.h"

static char* test_derived_root_secrets()
{
	struct derived_root_secrets derived_root_secrets;
	memset(&derived_root_secrets, 0, sizeof derived_root_secrets);

	mu_assert("", DERIVED_ROOT_SECRETS_SIZE == 64);

	unsigned char in[DERIVED_ROOT_SECRETS_SIZE];
	for (unsigned char i = 0; i < DERIVED_ROOT_SECRETS_SIZE; i++) {
		in[i] = i;
	}

	derived_root_secrets_init(&derived_root_secrets, in);
	mu_assert("", 0 == memcmp(derived_root_secrets.root_key, in, 32));
	mu_assert("", 0 == memcmp(derived_root_secrets.chain_key, in + 32, 32));

	return 0;
}

int tests_run = 0;

static char* all_tests()
{
	mu_run_test(test_derived_root_secrets);
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

