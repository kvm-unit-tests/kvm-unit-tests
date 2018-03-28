/*
 * Release pages hypercall tests (DIAG 10)
 *
 * Copyright (c) 2018 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.vnet.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>

static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));
const unsigned long page0 = (unsigned long)pagebuf;
const unsigned long page1 = (unsigned long)(pagebuf + PAGE_SIZE);

/* Tells the host to release pages from guest real addresses start to
 * end. Parameters have to be page aligned, instruction is privileged.
 */
static inline void diag10(unsigned long start, unsigned long end)
{
	asm volatile (
		"diag	%0,%1,0x10\n"
		: : "a" (start), "a" (end));
}

/* Try freeing the prefix */
static void test_prefix(void)
{
	expect_pgm_int();
	diag10(0, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	expect_pgm_int();
	diag10(0x1000, 0x1000);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	expect_pgm_int();
	diag10(0, 0x1000);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
}

static void test_params(void)
{
	/* end < start */
	expect_pgm_int();
	diag10(page1, page0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	/* Unaligned start */
	expect_pgm_int();
	diag10((unsigned long) pagebuf + 42, page1);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	/* Unaligned end */
	expect_pgm_int();
	diag10(page0, (unsigned long) pagebuf + PAGE_SIZE + 42);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
}

static void test_priv(void)
{
	expect_pgm_int();
	enter_pstate();
	diag10(page0, page0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
}

int main(void)
{
	report_prefix_push("diag10");
	test_prefix();
	test_params();
	test_priv();
	return report_summary();
}
