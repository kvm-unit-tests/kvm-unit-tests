/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Storage key tests
 *
 * Copyright (c) 2018 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.vnet.ibm.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/mem.h>


static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));

static void test_set_mb(void)
{
	union skey skey, ret1, ret2;
	void *addr = (void *)0x10000 - 2 * PAGE_SIZE;
	void *end = (void *)0x10000;

	/* Multi block support came with EDAT 1 */
	if (!test_facility(8))
		return;

	skey.val = 0x30;
	while (addr < end)
		addr = set_storage_key_mb(addr, skey.val);

	ret1.val = get_storage_key(end - PAGE_SIZE) & (SKEY_ACC | SKEY_FP);
	ret2.val = get_storage_key(end - PAGE_SIZE * 2) & (SKEY_ACC | SKEY_FP);
	report(ret1.val == ret2.val && ret1.val == skey.val, "multi block");
}

static void test_chg(void)
{
	union skey skey1, skey2;

	skey1.val = 0x30;
	set_storage_key(pagebuf, skey1.val, 0);
	skey1.val = get_storage_key(pagebuf);
	pagebuf[0] = 3;
	skey2.val = get_storage_key(pagebuf);
	report(!skey1.str.ch && skey2.str.ch, "chg bit test");
}

static void test_set(void)
{
	union skey skey, ret;

	skey.val = 0x30;
	ret.val = get_storage_key(pagebuf);
	set_storage_key(pagebuf, skey.val, 0);
	ret.val = get_storage_key(pagebuf);
	/*
	 * For all set tests we only test the ACC and FP bits. RF and
	 * CH are set by the machine for memory references and changes
	 * and hence might change between a set and a get.
	 */
	report(skey.str.acc == ret.str.acc && skey.str.fp == ret.str.fp,
	       "set key test");
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
	set_storage_key(pagebuf, 0x30, 0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	skey.val = get_storage_key(pagebuf);
	report(skey.str.acc != 3, "skey did not change on exception");

	report_prefix_push("iske");
	if (is_zvm6) {
		/* There is a known bug with z/VM 6, so skip the test there */
		report_skip("not working on z/VM 6");
	} else {
		expect_pgm_int();
		enter_pstate();
		get_storage_key(pagebuf);
		check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	}
	report_prefix_pop();

	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("skey");
	if (test_facility(169)) {
		report_skip("storage key removal facility is active");
		goto done;
	}
	test_priv();
	test_set();
	test_set_mb();
	test_chg();
done:
	report_prefix_pop();
	return report_summary();
}
