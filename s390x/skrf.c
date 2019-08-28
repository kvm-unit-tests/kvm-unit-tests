/*
 * Storage key removal facility tests
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/mem.h>

static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));

static void test_facilities(void)
{
	report_prefix_push("facilities");
	report("!10", !test_facility(10));
	report("!14", !test_facility(14));
	report("!66", !test_facility(66));
	report("!145", !test_facility(145));
	report("!149", !test_facility(140));
	report_prefix_pop();
}

static void test_skey(void)
{
	report_prefix_push("sske");
	expect_pgm_int();
	set_storage_key(pagebuf, 0x30, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	expect_pgm_int();
	report_prefix_pop();
	report_prefix_push("iske");
	get_storage_key(pagebuf);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_pfmf(void)
{
	union pfmf_r1 r1;

	report_prefix_push("pfmf");
	r1.val = 0;
	r1.reg.sk = 1;
	r1.reg.fsc = PFMF_FSC_4K;
	r1.reg.key = 0x30;
	expect_pgm_int();
	pfmf(r1.val, pagebuf);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_psw_key(void)
{
	uint64_t psw_mask = extract_psw_mask() | 0xF0000000000000UL;

	report_prefix_push("psw key");
	expect_pgm_int();
	load_psw_mask(psw_mask);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_mvcos(void)
{
	uint64_t r3 = 64;
	uint8_t *src = pagebuf;
	uint8_t *dst = pagebuf + PAGE_SIZE;
	/* K bit set, as well as keys */
	register unsigned long oac asm("0") = 0xf002f002;

	report_prefix_push("mvcos");
	expect_pgm_int();
	asm volatile("mvcos	%[dst],%[src],%[len]"
		     : [dst] "+Q" (*(dst))
		     : [src] "Q" (*(src)), [len] "d" (r3), "d" (oac)
		     : "cc", "memory");
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_spka(void)
{
	report_prefix_push("spka");
	expect_pgm_int();
	asm volatile("spka	0xf0(0)\n");
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_tprot(void)
{
	report_prefix_push("tprot");
	expect_pgm_int();
	asm volatile("tprot	%[addr],0xf0(0)\n"
		     : : [addr] "a" (pagebuf) : );
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("skrf");
	if (!test_facility(169)) {
		report_skip("storage key removal facility not available\n");
		goto done;
	}

	test_facilities();
	test_skey();
	test_pfmf();
	test_psw_key();
	test_mvcos();
	test_spka();
	test_tprot();

done:
	report_prefix_pop();
	return report_summary();
}
