/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Virtualization library that speeds up managing guests.
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */

#include <asm/barrier.h>
#include <libcflat.h>
#include <sie.h>

static bool validity_expected;
static uint16_t vir;		/* Validity interception reason */

void sie_expect_validity(void)
{
	validity_expected = true;
	vir = 0;
}

void sie_check_validity(uint16_t vir_exp)
{
	report(vir_exp == vir, "VALIDITY: %x", vir);
	vir = 0;
}

void sie_handle_validity(struct vm *vm)
{
	if (vm->sblk->icptcode != ICPT_VALIDITY)
		return;

	vir = vm->sblk->ipb >> 16;

	if (!validity_expected)
		report_abort("VALIDITY: %x", vir);
	validity_expected = false;
}
