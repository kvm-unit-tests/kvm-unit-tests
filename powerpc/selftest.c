/*
 * Test the framework itself. These tests confirm that setup works.
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <util.h>
#include <asm/setup.h>

static void check_setup(int argc, char **argv)
{
	int nr_tests = 0, len, i;
	long val;

	for (i = 0; i < argc; ++i) {

		len = parse_keyval(argv[i], &val);
		if (len == -1)
			continue;

		argv[i][len] = '\0';
		report_prefix_push(argv[i]);

		if (strcmp(argv[i], "mem") == 0) {

			phys_addr_t memsize = PHYSICAL_END - PHYSICAL_START;
			phys_addr_t expected = ((phys_addr_t)val)*1024*1024;

			report("size = %d MB", memsize == expected,
							memsize/1024/1024);
			++nr_tests;

		} else if (strcmp(argv[i], "smp") == 0) {

			report("nr_cpus = %d", nr_cpus == (int)val, nr_cpus);
			++nr_tests;
		}

		report_prefix_pop();
	}

	if (nr_tests < 2)
		report_abort("missing input");
}

int main(int argc, char **argv)
{
	report_prefix_push("selftest");

	if (!argc)
		report_abort("no test specified");

	report_prefix_push(argv[0]);

	if (strcmp(argv[0], "setup") == 0) {

		check_setup(argc-1, &argv[1]);

	}

	return report_summary();
}
