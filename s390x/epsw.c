/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * EPSW Interception Tests
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <css.h>
#include <hardware.h>

static uint32_t zero_out_cc_from_epsw_op1(uint32_t epsw_op1)
{
	return epsw_op1 & ~GENMASK(31 - 18, 31 - 20);
}

static void generate_crw(void)
{
	int test_device_sid = css_enumerate();
	int cc, ret;

	if (!(test_device_sid & SCHID_ONE)) {
		report_fail("No I/O device found");
		return;
	}

	cc = css_enable(test_device_sid, IO_SCH_ISC);
	report(cc == 0, "Enable subchannel %08x", test_device_sid);

	ret = css_generate_crw(test_device_sid);
	if (ret)
		report_fail("Couldn't generate CRW");
}

static void test_epsw(void)
{
	const uint64_t MAGIC1 = 0x1234567890abcdefUL;
	const uint64_t MAGIC2 = 0xcafedeadbeeffaceUL;

	uint64_t op1 = MAGIC1;
	uint64_t op2 = MAGIC2;
	uint32_t prev_epsw_op1;

	/*
	 * having machine check interrupts masked and pending CRW ensures
	 * EPSW is intercepted under KVM
	 */
	generate_crw();

	report_prefix_push("both operands given");
	asm volatile(
		"epsw %0, %1\n"
		: "+&d" (op1), "+&a" (op2));
	report(upper_32_bits(op1) == upper_32_bits(MAGIC1) &&
	       upper_32_bits(op2) == upper_32_bits(MAGIC2),
	       "upper 32 bits unmodified");
	report(lower_32_bits(op1) != lower_32_bits(MAGIC1) &&
	       lower_32_bits(op2) != lower_32_bits(MAGIC2),
	       "lower 32 bits modified");
	prev_epsw_op1 = zero_out_cc_from_epsw_op1(lower_32_bits(op1));
	report_prefix_pop();

	report_prefix_push("second operand 0");
	op1 = MAGIC1;
	op2 = MAGIC2;
	asm volatile(
		"	lgr 0,%[op2]\n"
		"	epsw %[op1], 0\n"
		"	lgr %[op2],0\n"
		: [op2] "+&d" (op2), [op1] "+&a" (op1)
		:
		: "0");
	report(upper_32_bits(op1) == upper_32_bits(MAGIC1),
	       "upper 32 bits of first operand unmodified");
	report(zero_out_cc_from_epsw_op1(lower_32_bits(op1)) == prev_epsw_op1,
	       "first operand matches previous reading");
	report(op2 == MAGIC2, "r0 unmodified");
	report_prefix_pop();

	report_prefix_push("both operands 0");
	op1 = MAGIC1;
	asm volatile(
		"	lgr 0,%[op1]\n"
		"	epsw 0, 0\n"
		"	lgr %[op1],0\n"
		: [op1] "+&d" (op1)
		:
		: "0");
	report(upper_32_bits(op1) == upper_32_bits(MAGIC1),
	       "upper 32 bits of first operand unmodified");
	report(zero_out_cc_from_epsw_op1(lower_32_bits(op1)) == prev_epsw_op1,
	       "first operand matches previous reading");
	report_prefix_pop();
}

int main(int argc, char **argv)
{
	report_prefix_push("epsw");

	if (!host_is_kvm() && !host_is_tcg()) {
		report_skip("Not running under QEMU");
		goto done;
	}

	test_epsw();

done:
	report_prefix_pop();

	return report_summary();
}
