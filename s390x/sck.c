/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Perform Set Clock tests
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <uv.h>
#include <asm/interrupt.h>
#include <asm/time.h>

static void test_priv(void)
{
	uint64_t time_to_set_privileged = 0xfacef00dcafe0000,
	    time_to_set_nonprivileged = 0xcafe0000,
	    time_verify;
	int cc;

	report_prefix_push("privileged");
	cc = sck(&time_to_set_privileged);
	report(!cc, "set clock cc=%d", cc);

	cc = stck(&time_verify);
	report(!cc, "store clock cc=%d", cc);
	report(time_verify > time_to_set_privileged,
	       "privileged set affected the clock");
	report_prefix_pop();

	report_prefix_push("unprivileged");
	expect_pgm_int();
	enter_pstate();
	sck(&time_to_set_nonprivileged);
	leave_pstate();
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);

	cc = stck(&time_verify);
	report(!cc, "store clock cc=%d", cc);
	report(time_verify > time_to_set_privileged,
	       "unprivileged set did not affect the clock");
	report_prefix_pop();
}

static void test_align(void)
{
	const int align_to = 8;
	char unalign[sizeof(uint64_t) + align_to] __attribute__((aligned(8)));

	report_prefix_push("Unaligned operand");
	for (int i = 1; i < align_to; i *= 2) {
		report_prefix_pushf("%d", i);
		expect_pgm_int();
		sck((uint64_t *)(unalign + i));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
		report_prefix_pop();
	}
	report_prefix_pop();
}

static void test_set(void)
{
	uint64_t start = 0, end = 0, time = 0xcafef00dbeef;
	const uint64_t ticks_per_ms = 1000 << 12, ms_to_wait = 5;
	int cc;

	report_prefix_push("set");

	cc = sck(&time);
	report(!cc, "set clock cc=%d", cc);

	cc = stck(&start);
	report(!cc, "store start clock cc=%d", cc);
	report(start >= time, "start >= set value");

	mdelay(ms_to_wait);

	cc = stck(&end);
	report(!cc, "store end clock cc=%d", cc);
	report(end > time, "end > set value");

	report(end - start > (ticks_per_ms * ms_to_wait), "Advances");

	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("sck");

	if (uv_os_is_guest()) {
		report_skip("Test unsupported under PV");
		goto out;
	}

	test_align();
	test_set();
	test_priv();

out:
	report_prefix_pop();
	return report_summary();
}
