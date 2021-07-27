/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Instruction Execution Prevention (IEP) DAT test.
 *
 * Copyright (c) 2018 IBM Corp
 *
 * Authors:
 *	Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <vmalloc.h>
#include <asm/facility.h>
#include <asm/interrupt.h>
#include <mmu.h>
#include <asm/pgtable.h>
#include <asm-generic/barrier.h>

static void test_iep(void)
{
	uint16_t *code;
	uint8_t *iepbuf = NULL;
	void (*fn)(void);

	/* Enable IEP */
	ctl_set_bit(0, CTL0_IEP);

	/* Get and protect a page with the IEP bit */
	iepbuf = alloc_page();
	protect_page(iepbuf, PAGE_ENTRY_IEP);

	/* Code branches into r14 which contains the return address. */
	code = (uint16_t *)iepbuf;
	*code = 0x07fe;
	fn = (void *)code;

	report_prefix_push("iep protection");
	expect_pgm_int();
	/* Jump into protected page */
	fn();
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report_prefix_pop();
	unprotect_page(iepbuf, PAGE_ENTRY_IEP);
	ctl_clear_bit(0, CTL0_IEP);
	free_page(iepbuf);
}

int main(void)
{
	bool has_iep = test_facility(130);

	report_prefix_push("iep");
	if (!has_iep) {
		report_skip("DAT IEP is not available");
		goto done;
	}

	/* Setup DAT 1:1 mapping and memory management */
	setup_vm();
	test_iep();

done:
	report_prefix_pop();
	return report_summary();
}
