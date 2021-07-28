/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Snippet used by the mvpg-sie.c test to check SIE PEI intercepts.
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>

static inline void force_exit(void)
{
	asm volatile("	diag	0,0,0x44\n");
}

static inline int mvpg(unsigned long r0, void *dest, void *src)
{
	register unsigned long reg0 asm ("0") = r0;
	int cc;

	asm volatile("	mvpg    %1,%2\n"
		     "	ipm     %0\n"
		     "	srl     %0,28"
		     : "=d" (cc) : "a" (dest), "a" (src), "d" (reg0)
		     : "memory", "cc");
	return cc;
}

static void test_mvpg_real(void)
{
	mvpg(0, (void *)0x5000, (void *)0x6000);
	force_exit();
}

__attribute__((section(".text"))) int main(void)
{
	test_mvpg_real();
	test_mvpg_real();
	test_mvpg_real();
	return 0;
}
