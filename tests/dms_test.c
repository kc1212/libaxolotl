
#include <stdio.h>
#include <sodium.h>

#include "minunit.h"
#include "../src/kdf/derived_message_secrets.h"

static char* test_dms()
{
	struct dms_data dms;

	mu_assert("", DMS_SIZE == DMS_CIPHER_KEY_LEN + DMS_MAC_KEY_LEN + DMS_IV_LEN);

	unsigned char in[DMS_SIZE];
	for (unsigned char i = 0; i < DMS_SIZE; i++) {
		in[i] = i;
	}

	dms_init(in, &dms);
	mu_assert("", 0 == sodium_memcmp(dms.cipher_key, in, DMS_CIPHER_KEY_LEN));
	mu_assert("", 0 == sodium_memcmp(dms.mac_key, in + DMS_CIPHER_KEY_LEN, DMS_MAC_KEY_LEN));
	mu_assert("", 0 == sodium_memcmp(dms.iv, in + DMS_CIPHER_KEY_LEN + DMS_MAC_KEY_LEN, DMS_IV_LEN));

	return 0;
}

int tests_run = 0;

static char* all_tests()
{
	mu_run_test(test_dms);
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

