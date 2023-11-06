/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
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

	report(c == 1.5, "3.0/2.0 == 1.5");
}

static void test_pgm_int(void)
{
	expect_pgm_int();
	asm volatile("	.insn e,0x0000"); /* used for SW breakpoints in QEMU */
	check_pgm_int_code(PGM_INT_CODE_OPERATION);

	expect_pgm_int();
	asm volatile("	stg %0,0(%0)\n" : : "a"(-1L));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

static void test_malloc(void)
{
	int *tmp, *tmp2;

	report_prefix_push("malloc");

	report_prefix_push("ptr_0");
	tmp = malloc(sizeof(int));
	report((uintptr_t)tmp & 0xf000000000000000ul, "allocated memory");
	*tmp = 123456789;
	mb();
	report(*tmp == 123456789, "wrote allocated memory");
	report_prefix_pop();

	report_prefix_push("ptr_1");
	tmp2 = malloc(sizeof(int));
	report((uintptr_t)tmp2 & 0xf000000000000000ul,
	       "allocated memory");
	*tmp2 = 123456789;
	mb();
	report((*tmp2 == 123456789), "wrote allocated memory");
	report_prefix_pop();

	report(tmp != tmp2, "allocated memory addresses differ");

	expect_pgm_int();
	disable_dat();
	*tmp = 987654321;
	enable_dat();
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);

	free(tmp);
	free(tmp2);
	report_prefix_pop();
}

static void test_psw_mask(void)
{
	uint64_t expected_key = 0xf;
	struct psw test_psw = PSW(0, 0);

	report_prefix_push("PSW mask");
	test_psw.mask = PSW_MASK_DAT;
	report(test_psw.dat, "DAT matches expected=0x%016lx actual=0x%016lx", PSW_MASK_DAT, test_psw.mask);

	test_psw.mask = PSW_MASK_IO;
	report(test_psw.io, "IO matches expected=0x%016lx actual=0x%016lx", PSW_MASK_IO, test_psw.mask);

	test_psw.mask = PSW_MASK_EXT;
	report(test_psw.ext, "EXT matches expected=0x%016lx actual=0x%016lx", PSW_MASK_EXT, test_psw.mask);

	test_psw.mask = expected_key << (63 - 11);
	report(test_psw.key == expected_key, "PSW Key matches expected=0x%lx actual=0x%x", expected_key, test_psw.key);

	test_psw.mask = 1UL << (63 - 13);
	report(test_psw.mchk, "MCHK matches");

	test_psw.mask = PSW_MASK_WAIT;
	report(test_psw.wait, "Wait matches expected=0x%016lx actual=0x%016lx", PSW_MASK_WAIT, test_psw.mask);

	test_psw.mask = PSW_MASK_PSTATE;
	report(test_psw.pstate, "Pstate matches expected=0x%016lx actual=0x%016lx", PSW_MASK_PSTATE, test_psw.mask);

	test_psw.mask = PSW_MASK_64;
	report(test_psw.ea && test_psw.ba, "BA/EA matches expected=0x%016lx actual=0x%016lx", PSW_MASK_64, test_psw.mask);

	report_prefix_pop();
}

int main(int argc, char**argv)
{
	report_prefix_push("selftest");

	report_pass("true");
	report(argc == 3, "argc == 3");
	report(!strcmp(argv[0], "s390x/selftest.elf"), "argv[0] == PROGNAME");
	report(!strcmp(argv[1], "test"), "argv[1] == test");
	report(!strcmp(argv[2], "123"), "argv[2] == 123");

	setup_vm();

	test_fp();
	test_pgm_int();
	test_malloc();
	test_psw_mask();

	return report_summary();
}
