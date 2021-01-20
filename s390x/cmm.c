/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CMM tests (ESSA)
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

static uint8_t pagebuf[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static unsigned long essa(uint8_t state, unsigned long paddr)
{
	uint64_t extr_state;

	asm volatile(".insn rrf,0xb9ab0000,%[extr_state],%[addr],%[new_state],0"
			: [extr_state] "=d" (extr_state)
			: [addr] "a" (paddr), [new_state] "i" (state));
	return (unsigned long)extr_state;
}

static void test_params(void)
{
	report_prefix_push("invalid ORC 8");
	expect_pgm_int();
	essa(8, (unsigned long)pagebuf);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static void test_priv(void)
{
	report_prefix_push("privileged");
	expect_pgm_int();
	enter_pstate();
	essa(0, (unsigned long)pagebuf);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

/* Unfortunately the availability is not indicated by stfl bits, but
 * we have to try to execute it and test for an operation exception.
 */
static bool test_availability(void)
{
	expect_pgm_int();
	essa(0, (unsigned long)pagebuf);
	return clear_pgm_int() == 0;
}

int main(void)
{
	bool has_essa = test_availability();

	report_prefix_push("cmm");
	if (!has_essa) {
		report_skip("ESSA is not available");
		goto done;
	}

	test_priv();
	test_params();
done:
	report_prefix_pop();
	return report_summary();
}
