/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Program interrupt loop test
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <bitops.h>
#include <asm/interrupt.h>
#include <asm/barrier.h>
#include <hardware.h>

int main(void)
{
	report_prefix_push("panic-loop-pgm");

	if (!host_is_qemu() || host_is_tcg()) {
		report_skip("QEMU-KVM-only test");
		goto out;
	}

	expect_pgm_int();
	/* bit 12 set is invalid */
	lowcore.pgm_new_psw.mask = extract_psw_mask() | BIT(63 - 12);
	mb();

	/* cause a pgm int */
	psw_mask_set_bits(BIT(63 - 12));

	report_fail("survived pgm int loop");

out:
	report_prefix_pop();
	return report_summary();
}
