
#include <stdio.h>
#include <string.h>

#include "minunit.h"
#include "../src/derived_message_secrets.h"

static char* test_dms()
{
	struct dms_data dms;
	memset(&dms, 0, sizeof dms);

	mu_assert("", DMS_SIZE == DMS_CIPHER_KEY_LEN + DMS_MAC_KEY_LEN + DMS_IV_LEN);

	unsigned char in[DMS_SIZE];
	for (unsigned char i = 0; i < DMS_SIZE; i++) {
		in[i] = i;
	}

	dms_init(&dms, in);
	mu_assert("", 0 == memcmp(dms.cipher_key, in, DMS_CIPHER_KEY_LEN));
	mu_assert("", 0 == memcmp(dms.mac_key, in + DMS_CIPHER_KEY_LEN, DMS_MAC_KEY_LEN));
	mu_assert("", 0 == memcmp(dms.iv, in + DMS_CIPHER_KEY_LEN + DMS_MAC_KEY_LEN, DMS_IV_LEN));

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

