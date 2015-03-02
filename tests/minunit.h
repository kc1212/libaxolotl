/* file: minunit.h */

#ifndef _minunit_h
#define _minunit_h

#include <string.h>

#define mu_assert(message, test) \
	do { \
		if (!(test)) \
			return "FAIL> "message"> "#test; \
	} while (0)

#define mu_run_test(test) \
	do { \
		char *message = test(); \
		tests_run++; \
		if (message) \
			return message; \
		else { \
			printf("ok> "); \
			printf(#test"\n"); \
		} \
	} while (0)

extern int tests_run;

#endif
