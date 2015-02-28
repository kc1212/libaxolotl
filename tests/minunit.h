/* file: minunit.h */

#ifndef _minunit_h
#define _minunit_h

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
			printf(#test); \
			for (size_t i = 0; i < 30 - strlen(#test); i++) \
				printf("."); \
			printf("PASSED\n"); \
		} \
	} while (0)

extern int tests_run;

#endif
