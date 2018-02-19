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
#include <alloc.h>
#include <asm/interrupt.h>
#include <asm/barrier.h>
#include <asm/pgtable.h>

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

static void test_pgm_int(void)
{
	expect_pgm_int();
	asm volatile("	.insn e,0x0000"); /* used for SW breakpoints in QEMU */
	check_pgm_int_code(PGM_INT_CODE_OPERATION);

	expect_pgm_int();
	asm volatile("	stg %0,0(%0)\n" : : "r"(-1L));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

static void test_malloc(void)
{
	int *tmp = malloc(sizeof(int));
	int *tmp2 = malloc(sizeof(int));

	*tmp = 123456789;
	*tmp2 = 123456789;
	mb();

	report("malloc: got vaddr", (uintptr_t)tmp & 0xf000000000000000ul);
	report("malloc: access works", *tmp == 123456789);
	report("malloc: got 2nd vaddr", (uintptr_t)tmp2 & 0xf000000000000000ul);
	report("malloc: access works", (*tmp2 == 123456789));
	report("malloc: addresses differ", tmp != tmp2);

	expect_pgm_int();
	configure_dat(0);
	*tmp = 987654321;
	configure_dat(1);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);

	free(tmp);
	free(tmp2);
}

int main(int argc, char**argv)
{
	report_prefix_push("selftest");

	report("true", true);
	report("argc == 3", argc == 3);
	report("argv[0] == PROGNAME", !strcmp(argv[0], "s390x/selftest.elf"));
	report("argv[1] == test", !strcmp(argv[1], "test"));
	report("argv[2] == 123", !strcmp(argv[2], "123"));

	setup_vm();

	test_fp();
	test_pgm_int();
	test_malloc();

	return report_summary();
}
