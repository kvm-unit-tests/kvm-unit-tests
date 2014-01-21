/*
 * Test the framework itself. These tests confirm that setup works.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "asm/setup.h"

#define TESTGRP "selftest"

static char testname[64];

static void testname_set(const char *subtest)
{
	strcpy(testname, TESTGRP);
	if (subtest) {
		strcat(testname, "::");
		strcat(testname, subtest);
	}
}

static void assert_args(int num_args, int needed_args)
{
	if (num_args < needed_args) {
		printf("%s: not enough arguments\n", testname);
		abort();
	}
}

static char *split_var(char *s, long *val)
{
	char *p;

	p = strchr(s, '=');
	if (!p)
		return NULL;

	*val = atol(p+1);
	*p = '\0';

	return s;
}

static void check_setup(int argc, char **argv)
{
	int nr_tests = 0, i;
	char *var;
	long val;

	for (i = 0; i < argc; ++i) {

		var = split_var(argv[i], &val);
		if (!var)
			continue;

		if (strcmp(var, "mem") == 0) {

			phys_addr_t memsize = PHYS_END - PHYS_OFFSET;
			phys_addr_t expected = ((phys_addr_t)val)*1024*1024;

			report("%s[%s]", memsize == expected, testname, "mem");
			++nr_tests;

		} else if (strcmp(var, "smp") == 0) {

			report("%s[%s]", nr_cpus == (int)val, testname, "smp");
			++nr_tests;
		}
	}

	assert_args(nr_tests, 2);
}

int main(int argc, char **argv)
{
	testname_set(NULL);
	assert_args(argc, 1);
	testname_set(argv[0]);

	if (strcmp(argv[0], "setup") == 0)
		check_setup(argc-1, &argv[1]);

	return report_summary();
}
