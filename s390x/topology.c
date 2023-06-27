/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CPU Topology
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 */

#include <libcflat.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/facility.h>
#include <asm/barrier.h>
#include <smp.h>
#include <sclp.h>
#include <s390x/hardware.h>

#define PTF_REQ_HORIZONTAL	0
#define PTF_REQ_VERTICAL	1
#define PTF_CHECK		2

#define PTF_ERR_NO_REASON	0
#define PTF_ERR_ALRDY_POLARIZED	1
#define PTF_ERR_IN_PROGRESS	2

extern int diag308_load_reset(u64);

static int ptf(unsigned long fc, unsigned long *rc)
{
	int cc;

	asm volatile(
		"	ptf	%1	\n"
		"       ipm     %0	\n"
		"       srl     %0,28	\n"
		: "=d" (cc), "+d" (fc)
		:
		: "cc");

	*rc = fc >> 8;
	return cc;
}

static void check_privilege(int fc)
{
	unsigned long rc;

	report_prefix_pushf("Privileged fc %d", fc);
	enter_pstate();
	expect_pgm_int();
	ptf(fc, &rc);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static void check_specifications(void)
{
	unsigned long error = 0;
	unsigned long ptf_bits;
	unsigned long rc;
	int i;

	report_prefix_push("Specifications");

	/* Function codes above 3 are undefined */
	for (i = 4; i < 255; i++) {
		expect_pgm_int();
		ptf(i, &rc);
		if (clear_pgm_int() != PGM_INT_CODE_SPECIFICATION) {
			report_fail("FC %d did not yield specification exception", i);
			error = 1;
		}
	}
	report(!error, "Undefined function codes");

	/* Reserved bits must be 0 */
	for (i = 8, error = 0; i < 64; i++) {
		ptf_bits = 0x01UL << i;
		expect_pgm_int();
		ptf(ptf_bits, &rc);
		if (clear_pgm_int() != PGM_INT_CODE_SPECIFICATION) {
			report_fail("Reserved bit %d did not yield specification exception", i);
			error = 1;
		}
	}

	report(!error, "Reserved bits");

	report_prefix_pop();
}

static void check_polarization_change(void)
{
	unsigned long rc;
	int cc;

	report_prefix_push("Polarization change");

	/* We expect a clean state through reset */
	report(diag308_load_reset(1), "load normal reset done");

	/*
	 * Set vertical polarization to verify that RESET sets
	 * horizontal polarization back.
	 */
	cc = ptf(PTF_REQ_VERTICAL, &rc);
	report(cc == 0, "Set vertical polarization.");

	report(diag308_load_reset(1), "load normal reset done");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 0, "Reset should clear topology report");

	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	report(cc == 2 && rc == PTF_ERR_ALRDY_POLARIZED,
	       "After RESET polarization is horizontal");

	/* Flip between vertical and horizontal polarization */
	cc = ptf(PTF_REQ_VERTICAL, &rc);
	report(cc == 0, "Change to vertical");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 1, "Should report");

	cc = ptf(PTF_REQ_VERTICAL, &rc);
	report(cc == 2 && rc == PTF_ERR_ALRDY_POLARIZED, "Double change to vertical");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 0, "Should not report");

	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	report(cc == 0, "Change to horizontal");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 1, "Should Report");

	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	report(cc == 2 && rc == PTF_ERR_ALRDY_POLARIZED, "Double change to horizontal");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 0, "Should not report");

	report_prefix_pop();
}

static void test_ptf(void)
{
	check_privilege(PTF_REQ_HORIZONTAL);
	check_privilege(PTF_REQ_VERTICAL);
	check_privilege(PTF_CHECK);
	check_specifications();
	check_polarization_change();
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "PTF", test_ptf },
	{ NULL, NULL }
};

int main(int argc, char *argv[])
{
	int i;

	report_prefix_push("CPU Topology");

	if (!test_facility(11)) {
		report_skip("Topology facility not present");
		goto end;
	}

	report_info("Virtual machine level %ld", stsi_get_fc());

	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}

end:
	report_prefix_pop();
	return report_summary();
}
