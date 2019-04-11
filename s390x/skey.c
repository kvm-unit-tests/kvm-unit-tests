/*
 * Storage key tests
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
#include <asm/facility.h>
#include <asm/mem.h>


static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));
const unsigned long page0 = (unsigned long)pagebuf;
const unsigned long page1 = (unsigned long)(pagebuf + PAGE_SIZE);

static void test_set_mb(void)
{
	union skey skey, ret1, ret2;
	unsigned long addr = 0x10000 - 2 * PAGE_SIZE;
	unsigned long end = 0x10000;

	/* Multi block support came with EDAT 1 */
	if (!test_facility(8))
		return;

	skey.val = 0x30;
	while (addr < end)
		addr = set_storage_key_mb(addr, skey.val);

	ret1.val = get_storage_key(end - PAGE_SIZE) & (SKEY_ACC | SKEY_FP);
	ret2.val = get_storage_key(end - PAGE_SIZE * 2) & (SKEY_ACC | SKEY_FP);
	report("multi block",
	       ret1.val == ret2.val && ret1.val == skey.val);
}

static void test_chg(void)
{
	union skey skey1, skey2;

	skey1.val = 0x30;
	set_storage_key(page0, skey1.val, 0);
	skey1.val = get_storage_key(page0);
	pagebuf[0] = 3;
	skey2.val = get_storage_key(page0);
	report("chg bit test", !skey1.str.ch && skey2.str.ch);
}

static void test_set(void)
{
	union skey skey, ret;

	skey.val = 0x30;
	ret.val = get_storage_key(page0);
	set_storage_key(page0, skey.val, 0);
	ret.val = get_storage_key(page0);
	/*
	 * For all set tests we only test the ACC and FP bits. RF and
	 * CH are set by the machine for memory references and changes
	 * and hence might change between a set and a get.
	 */
	report("set key test",
	       skey.str.acc == ret.str.acc && skey.str.fp == ret.str.fp);
}

static inline int stsi(void *addr, int fc, int sel1, int sel2)
{
	register int r0 asm("0") = (fc << 28) | sel1;
	register int r1 asm("1") = sel2;
	int rc = 0;

	asm volatile(
		"	stsi	0(%3)\n"
		"	jz	0f\n"
		"	lhi	%1,-1\n"
		"0:\n"
		: "+d" (r0), "+d" (rc)
		: "d" (r1), "a" (addr)
		: "cc", "memory");

	return rc;
}

/* Returns true if we are running under z/VM 6.x */
static bool check_for_zvm6(void)
{
	int dcbt;	/* Descriptor block count */
	int nr;
	static const unsigned char zvm6[] = {
		/* This is "z/VM    6" in EBCDIC */
		0xa9, 0x61, 0xe5, 0xd4, 0x40, 0x40, 0x40, 0x40, 0xf6
	};

	if (stsi(pagebuf, 3, 2, 2))
		return false;

	dcbt = pagebuf[31] & 0xf;

	for (nr = 0; nr < dcbt; nr++) {
		if (!memcmp(&pagebuf[32 + nr * 64 + 24], zvm6, sizeof(zvm6)))
			return true;
	}

	return false;
}

static void test_priv(void)
{
	union skey skey;
	bool is_zvm6 = check_for_zvm6();

	memset(pagebuf, 0, PAGE_SIZE * 2);
	report_prefix_push("privileged");
	report_prefix_push("sske");
	expect_pgm_int();
	enter_pstate();
	set_storage_key(page0, 0x30, 0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	skey.val = get_storage_key(page0);
	report("skey did not change on exception", skey.str.acc != 3);

	report_prefix_push("iske");
	if (is_zvm6) {
		/* There is a known bug with z/VM 6, so skip the test there */
		report_skip("not working on z/VM 6");
	} else {
		expect_pgm_int();
		enter_pstate();
		get_storage_key(page0);
		check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	}
	report_prefix_pop();

	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("skey");
	test_priv();
	test_set();
	test_set_mb();
	test_chg();
	report_prefix_pop();
	return report_summary();
}
