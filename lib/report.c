/*
 * Test result reporting
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#include "libcflat.h"

static unsigned int tests, failures;

void report(const char *msg_fmt, bool pass, ...)
{
	char buf[2000];
	va_list va;

	tests++;
	printf("%s: ", pass ? "PASS" : "FAIL");
	va_start(va, pass);
	vsnprintf(buf, sizeof(buf), msg_fmt, va);
	va_end(va);
	puts(buf);
	puts("\n");
	if (!pass)
		failures++;
}

int report_summary(void)
{
	printf("\nSUMMARY: %d tests, %d failures\n", tests, failures);
	return failures > 0 ? 1 : 0;
}
