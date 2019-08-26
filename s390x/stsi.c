/*
 * Store System Information tests
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <libcflat.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>

static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));

static void test_specs(void)
{
	report_prefix_push("specification");

	report_prefix_push("inv r0");
	expect_pgm_int();
	stsi(pagebuf, 0, 1 << 8, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("inv r1");
	expect_pgm_int();
	stsi(pagebuf, 1, 0, 1 << 16);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("unaligned");
	expect_pgm_int();
	stsi(pagebuf + 42, 1, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_pop();
}

static void test_priv(void)
{
	report_prefix_push("privileged");
	expect_pgm_int();
	enter_pstate();
	stsi(pagebuf, 0, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static inline unsigned long stsi_get_fc(void *addr)
{
	register unsigned long r0 asm("0") = 0;
	register unsigned long r1 asm("1") = 0;
	int cc;

	asm volatile("stsi	0(%[addr])\n"
		     "ipm	%[cc]\n"
		     "srl	%[cc],28\n"
		     : "+d" (r0), [cc] "=d" (cc)
		     : "d" (r1), [addr] "a" (addr)
		     : "cc", "memory");
	assert(!cc);
	return r0 >> 28;
}

static void test_fc(void)
{
	report("invalid fc",  stsi(pagebuf, 7, 0, 0) == 3);
	report("query fc >= 2",  stsi_get_fc(pagebuf) >= 2);
}

int main(void)
{
	report_prefix_push("stsi");
	test_priv();
	test_specs();
	test_fc();
	return report_summary();
}
