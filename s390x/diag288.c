/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Timer Event DIAG288 test
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */

#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>

struct lowcore *lc = (struct lowcore *)0x0;

#define CODE_INIT	0
#define CODE_CHANGE	1
#define CODE_CANCEL	2

#define ACTION_RESTART	0

static inline void diag288(unsigned long code, unsigned long time,
			   unsigned long action)
{
	register unsigned long fc asm("0") = code;
	register unsigned long tm asm("1") = time;
	register unsigned long ac asm("2") = action;

	asm volatile("diag %0,%2,0x288"
		     : : "d" (fc), "d" (tm), "d" (ac));
}

static void test_specs(void)
{
	report_prefix_push("specification");

	report_prefix_push("uneven");
	expect_pgm_int();
	asm volatile("diag 1,2,0x288");
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("unsupported action");
	expect_pgm_int();
	diag288(CODE_INIT, 15, 42);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("unsupported function");
	expect_pgm_int();
	diag288(42, 15, ACTION_RESTART);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("no init");
	expect_pgm_int();
	diag288(CODE_CANCEL, 15, ACTION_RESTART);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("min timer");
	expect_pgm_int();
	diag288(CODE_INIT, 14, ACTION_RESTART);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_pop();
}

static void test_priv(void)
{
	report_prefix_push("privileged");
	expect_pgm_int();
	enter_pstate();
	diag288(CODE_INIT, 15, ACTION_RESTART);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static void test_bite(void)
{
	uint64_t mask, time;

	/* If watchdog doesn't bite, the cpu timer does */
	asm volatile("stck %0" : "=Q" (time) : : "cc");
	time += (uint64_t)(16000 * 1000) << 12;
	asm volatile("sckc %0" : : "Q" (time));
	ctl_set_bit(0, CTL0_CLOCK_COMPARATOR);
	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);

	/* Arm watchdog */
	lc->restart_new_psw.mask = extract_psw_mask() & ~PSW_MASK_EXT;
	diag288(CODE_INIT, 15, ACTION_RESTART);
	asm volatile("		larl	%r0, 1f\n"
		     "		stg	%r0, 424\n"
		     "0:	nop\n"
		     "		j	0b\n"
		     "1:");
	report(true, "restart");
}

int main(void)
{
	report_prefix_push("diag288");
	test_priv();
	test_specs();
	test_bite();
	return report_summary();
}
