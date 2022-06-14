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
#include <asm/cmm.h>

static uint8_t pagebuf[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

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
	essa(ESSA_GET_STATE, (unsigned long)pagebuf);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

int main(void)
{
	bool has_essa = check_essa_available();

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
