#ifndef _UTIL_H_
#define _UTIL_H_
/*
 * Collection of utility functions to share between unit tests.
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

/*
 * parse_keyval extracts the integer from a string formatted as
 * string=integer. This is useful for passing expected values to
 * the unit test on the command line, i.e. it helps parse QEMU
 * command lines that include something like -append var1=1 var2=2
 * @s is the input string, likely a command line parameter, and
 * @val is a pointer to where the integer will be stored.
 *
 * Returns the offset of the '=', or -1 if no keyval pair is found.
 */
extern int parse_keyval(char *s, long *val);

#define __TEST_EQ(a, b, a_str, b_str, assertion, do_abort, fmt, args...)		\
do {											\
	typeof(a) _a = a;								\
	typeof(b) _b = b;								\
	if (_a != _b) {									\
		char _bin_a[BINSTR_SZ];							\
		char _bin_b[BINSTR_SZ];							\
		binstr(_a, _bin_a);							\
		binstr(_b, _bin_b);							\
		report_fail("%s:%d: %s failed: (%s) == (%s)\n"				\
			    "\tLHS: %#018lx - %s - %lu\n"				\
			    "\tRHS: %#018lx - %s - %lu%s" fmt,				\
			    __FILE__, __LINE__,						\
			    assertion ? "Assertion" : "Expectation", a_str, b_str,	\
			    (unsigned long) _a, _bin_a, (unsigned long) _a,		\
			    (unsigned long) _b, _bin_b, (unsigned long) _b,		\
			    fmt[0] == '\0' ? "" : "\n", ## args);			\
		dump_stack();								\
		if (assertion)								\
			do_abort();							\
	}										\
	report_passed();								\
} while (0)

/* FIXME: Extend VMX's assert/abort framework to SVM and other environs. */
static inline void dummy_abort(void) {}

#define TEST_EXPECT_EQ(a, b) __TEST_EQ(a, b, #a, #b, 0, dummy_abort, "")
#define TEST_EXPECT_EQ_MSG(a, b, fmt, args...) \
	__TEST_EQ(a, b, #a, #b, 0, dummy_abort fmt, ## args)

#endif
