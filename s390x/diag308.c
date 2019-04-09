/*
 * Diagnose 0x308 hypercall tests
 *
 * Copyright (c) 2019 Thomas Huth, Red Hat Inc.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2, or (at
 * your option) any later version.
 */

#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>

/* The diagnose calls should be blocked in problem state */
static void test_priv(void)
{
	expect_pgm_int();
	enter_pstate();
	asm volatile ("diag %0,%1,0x308" :: "d"(0), "d"(3));
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
}

/*
 * Check that diag308 with subcode 1 loads the PSW at address 0, i.e.
 * that we can put a pointer into address 4 which then gets executed.
 */
static void test_subcode1(void)
{
	uint64_t saved_psw = *(uint64_t *)0;
	long subcode = 1;
	long ret, tmp;

	asm volatile (
		"	epsw	%0,%1\n"
		"	st	%0,0\n"
		"	larl	%0,0f\n"
		"	oilh	%0,0x8000\n"
		"	st	%0,4\n"
		"	diag	0,%2,0x308\n"
		"	lghi	%0,0\n"
		"	j	1f\n"
		"0:	lghi	%0,1\n"
		"1:"
		: "=&d"(ret), "=&d"(tmp) : "d"(subcode) : "memory");

	*(uint64_t *)0 = saved_psw;

	report("load normal reset done", ret == 1);
}

/* Expect a specification exception when using an uneven register */
static void test_uneven_reg(unsigned int subcode)
{
	register unsigned long sc asm("6") = subcode;
	register unsigned long r3 asm("9") = 0x2000;

	report_prefix_push("uneven register");
	expect_pgm_int();
	asm volatile ("diag %0,%1,0x308" :: "d"(r3), "d"(sc));
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

/* Expect a specification exception when using an unaligned address */
static void test_unaligned_address(unsigned int subcode)
{
	register unsigned long sc asm("6") = subcode;
	register unsigned long addr asm("8") = 54321;

	report_prefix_push("unaligned address");
	expect_pgm_int();
	asm volatile ("diag %0,%1,0x308" :: "d"(addr), "d"(sc));
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static void test_subcode5(void)
{
	test_uneven_reg(5);
	test_unaligned_address(5);
}

static void test_subcode6(void)
{
	test_uneven_reg(6);
	test_unaligned_address(6);
}

/* Unsupported subcodes should generate a specification exception */
static void test_unsupported_subcode(void)
{
	int subcodes[] = { 2, 0x101, 0xffff, 0x10001, -1 };
	int idx;

	for (idx = 0; idx < ARRAY_SIZE(subcodes); idx++) {
		report_prefix_pushf("0x%04x", subcodes[idx]);
		expect_pgm_int();
		asm volatile ("diag %0,%1,0x308" :: "d"(0), "d"(subcodes[idx]));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
		report_prefix_pop();
	}
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "privileged", test_priv },
	{ "subcode 1", test_subcode1 },
	{ "subcode 5", test_subcode5 },
	{ "subcode 6", test_subcode6 },
	{ "unsupported", test_unsupported_subcode },
	{ NULL, NULL }
};

int main(int argc, char**argv)
{
	int i;

	report_prefix_push("diag308");
	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}
	report_prefix_pop();

	return report_summary();
}
