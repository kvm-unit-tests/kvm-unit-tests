/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Perform Frame Management Function (pfmf) tests
 *
 * Copyright (c) 2018 IBM
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

static uint8_t pagebuf[PAGE_SIZE * 256] __attribute__((aligned(PAGE_SIZE * 256)));

static void test_priv(void)
{
	report_prefix_push("privileged");
	expect_pgm_int();
	enter_pstate();
	pfmf(0, pagebuf);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static void test_4k_key(void)
{
	union pfmf_r1 r1;
	union skey skey;

	report_prefix_push("4K");
	if (test_facility(169)) {
		report_skip("storage key removal facility is active");
		goto out;
	}
	r1.val = 0;
	r1.reg.sk = 1;
	r1.reg.fsc = PFMF_FSC_4K;
	r1.reg.key = 0x30;
	pfmf(r1.val, pagebuf);
	skey.val = get_storage_key(pagebuf);
	skey.val &= SKEY_ACC | SKEY_FP;
	report(skey.val == 0x30, "set storage keys");
out:
	report_prefix_pop();
}

static void test_1m_key(void)
{
	int i;
	bool rp = true;
	union pfmf_r1 r1;
	union skey skey;

	report_prefix_push("1M");
	if (test_facility(169)) {
		report_skip("storage key removal facility is active");
		goto out;
	}
	r1.val = 0;
	r1.reg.sk = 1;
	r1.reg.fsc = PFMF_FSC_1M;
	r1.reg.key = 0x30;
	pfmf(r1.val, pagebuf);
	for (i = 0; i < 256; i++) {
		skey.val = get_storage_key(pagebuf + i * PAGE_SIZE);
		skey.val &= SKEY_ACC | SKEY_FP;
		if (skey.val != 0x30) {
			rp = false;
			break;
		}
	}
	report(rp, "set storage keys");
out:
	report_prefix_pop();
}

static void test_4k_clear(void)
{
	union pfmf_r1 r1;

	r1.val = 0;
	r1.reg.cf = 1;
	r1.reg.fsc = PFMF_FSC_4K;

	report_prefix_push("4K");
	memset(pagebuf, 42, PAGE_SIZE);
	pfmf(r1.val, pagebuf);
	report(!memcmp(pagebuf, pagebuf + PAGE_SIZE, PAGE_SIZE),
	       "clear memory");
	report_prefix_pop();
}

static void test_1m_clear(void)
{
	int i;
	union pfmf_r1 r1;
	unsigned long sum = 0;

	r1.val = 0;
	r1.reg.cf = 1;
	r1.reg.fsc = PFMF_FSC_1M;

	report_prefix_push("1M");
	memset(pagebuf, 42, PAGE_SIZE * 256);
	pfmf(r1.val, pagebuf);
	for (i = 0; i < PAGE_SIZE * 256; i++)
		sum |= pagebuf[i];
	report(!sum, "clear memory");
	report_prefix_pop();
}

int main(void)
{
	bool has_edat = test_facility(8);

	report_prefix_push("pfmf");
	if (!has_edat) {
		report_skip("PFMF is not available");
		goto done;
	}

	test_priv();
	/* Force the buffer pages in */
	memset(pagebuf, 0, PAGE_SIZE * 256);

	test_4k_key();
	test_4k_clear();
	test_1m_key();
	test_1m_clear();

done:
	report_prefix_pop();
	return report_summary();
}
