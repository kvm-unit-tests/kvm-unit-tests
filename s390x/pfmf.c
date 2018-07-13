/*
 * Perform Frame Management Function (pfmf) tests
 *
 * Copyright (c) 2018 IBM
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

#define FSC_4K 0
#define FSC_1M 1
#define FSC_2G 2

union r1 {
	struct {
		unsigned long pad0 : 32;
		unsigned long pad1 : 12;
		unsigned long pad_fmfi : 2;
		unsigned long sk : 1; /* set key*/
		unsigned long cf : 1; /* clear frame */
		unsigned long ui : 1; /* usage indication */
		unsigned long fsc : 3;
		unsigned long pad2 : 1;
		unsigned long mr : 1;
		unsigned long mc : 1;
		unsigned long pad3 : 1;
		unsigned long key : 8; /* storage keys */
	} reg;
	unsigned long val;
};

static uint8_t pagebuf[PAGE_SIZE * 256] __attribute__((aligned(PAGE_SIZE * 256)));

static inline unsigned long pfmf(unsigned long r1, unsigned long paddr)
{
	register uint64_t addr asm("1") = paddr;

	asm volatile(".insn rre,0xb9af0000,%[r1],%[addr]"
		     : [addr] "+a" (addr) : [r1] "d" (r1) : "memory");
	return addr;
}

static void test_priv(void)
{
	expect_pgm_int();
	enter_pstate();
	pfmf(0, (unsigned long) pagebuf);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
}

static void test_4k_key(void)
{
	union r1 r1;
	union skey skey;

	r1.val = 0;
	r1.reg.sk = 1;
	r1.reg.fsc = FSC_4K;
	r1.reg.key = 0x30;
	pfmf(r1.val, (unsigned long) pagebuf);
	skey.val = get_storage_key((unsigned long) pagebuf);
	report("set 4k", skey.val == 0x30);
}

static void test_1m_key(void)
{
	int i;
	union r1 r1;

	r1.val = 0;
	r1.reg.sk = 1;
	r1.reg.fsc = FSC_1M;
	r1.reg.key = 0x30;
	pfmf(r1.val, (unsigned long) pagebuf);
	for (i = 0; i < 256; i++) {
		if (get_storage_key((unsigned long) pagebuf + i * PAGE_SIZE) != 0x30) {
			report("set 1M", false);
			return;
		}
	}
	report("set 1M", true);
}

static void test_4k_clear(void)
{
	union r1 r1;

	r1.val = 0;
	r1.reg.cf = 1;
	r1.reg.fsc = FSC_4K;

	memset(pagebuf, 42, PAGE_SIZE);
	pfmf(r1.val, (unsigned long) pagebuf);
	report("clear 4k", !memcmp(pagebuf, pagebuf + PAGE_SIZE, PAGE_SIZE));
}

static void test_1m_clear(void)
{
	int i;
	union r1 r1;
	unsigned long sum = 0;

	r1.val = 0;
	r1.reg.cf = 1;
	r1.reg.fsc = FSC_1M;

	memset(pagebuf, 42, PAGE_SIZE * 256);
	pfmf(r1.val, (unsigned long) pagebuf);
	for (i = 0; i < PAGE_SIZE * 256; i++)
		sum |= pagebuf[i];
	report("clear 1m", !sum);
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
	test_1m_key();
	test_4k_clear();
	test_1m_clear();

done:
	report_prefix_pop();
	return report_summary();
}
