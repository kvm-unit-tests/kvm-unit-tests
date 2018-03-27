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

	ret1.val = get_storage_key(end - PAGE_SIZE);
	ret2.val = get_storage_key(end - PAGE_SIZE * 2);
	report("multi block", ret1.val == ret2.val && ret1.val == skey.val);
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
	report("set key test", skey.val == ret.val);
}

static void test_priv(void)
{
	union skey skey;

	memset(pagebuf, 0, PAGE_SIZE * 2);
	expect_pgm_int();
	enter_pstate();
	set_storage_key(page0, 0x30, 0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);

	skey.val = get_storage_key(page0);
	report("skey did not change on exception", skey.str.acc != 3);

	expect_pgm_int();
	enter_pstate();
	get_storage_key(page0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
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
