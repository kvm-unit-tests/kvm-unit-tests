/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#include <libcflat.h>
#include <util.h>

static void test_fp(void)
{
	double a = 3.0;
	double b = 2.0;
	double c;

	asm volatile(
		"	ddb %1, %2\n"
		"	std %1, %0\n"
		: "=m" (c) : "f" (a), "m" (b));

	report("3.0/2.0 == 1.5", c == 1.5);
}

int main(int argc, char**argv)
{
	report_prefix_push("selftest");

	report("true", true);
	report("argc == 3", argc == 3);
	report("argv[0] == PROGNAME", !strcmp(argv[0], "s390x/selftest.elf"));
	report("argv[1] == test", !strcmp(argv[1], "test"));
	report("argv[2] == 123", !strcmp(argv[2], "123"));

	test_fp();

	return report_summary();
}
