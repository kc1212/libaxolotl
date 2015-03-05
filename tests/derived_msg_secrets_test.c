
#include <stdio.h>
#include <string.h>

#include "minunit.h"
#include "../src/derived_msg_secrets.h"

static char* test_derived_msg_secrets()
{
	struct derived_msg_secrets derived_msg_secrets;
	memset(&derived_msg_secrets, 0, sizeof derived_msg_secrets);

	mu_assert("", DERIVED_MSG_SECRETS_SIZE ==
			DERIVED_MSG_SECRETS_CIPHER_KEY_LEN
			+ DERIVED_MSG_SECRETS_MAC_KEY_LEN
			+ DERIVED_MSG_SECRETS_IV_LEN);

	unsigned char in[DERIVED_MSG_SECRETS_SIZE];
	for (unsigned char i = 0; i < DERIVED_MSG_SECRETS_SIZE; i++) {
		in[i] = i;
	}

	derived_msg_secrets_init(&derived_msg_secrets, in);
	mu_assert("", 0 == memcmp(derived_msg_secrets.cipher_key, in,
				DERIVED_MSG_SECRETS_CIPHER_KEY_LEN));
	mu_assert("", 0 == memcmp(derived_msg_secrets.mac_key,
				in + DERIVED_MSG_SECRETS_CIPHER_KEY_LEN, DERIVED_MSG_SECRETS_MAC_KEY_LEN));
	mu_assert("", 0 == memcmp(derived_msg_secrets.iv,
				in + DERIVED_MSG_SECRETS_CIPHER_KEY_LEN + DERIVED_MSG_SECRETS_MAC_KEY_LEN,
				DERIVED_MSG_SECRETS_IV_LEN));

	return 0;
}

int tests_run = 0;

static char* all_tests()
{
	mu_run_test(test_derived_msg_secrets);
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

