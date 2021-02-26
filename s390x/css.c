/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Channel Subsystem tests
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 */

#include <libcflat.h>
#include <alloc_phys.h>
#include <asm/page.h>
#include <string.h>
#include <interrupt.h>
#include <asm/arch_def.h>
#include <alloc_page.h>

#include <malloc_io.h>
#include <css.h>
#include <asm/barrier.h>

#define DEFAULT_CU_TYPE		0x3832 /* virtio-ccw */
static unsigned long cu_type = DEFAULT_CU_TYPE;

static int test_device_sid;
static struct senseid *senseid;
struct ccw1 *ccw;

static void test_enumerate(void)
{
	test_device_sid = css_enumerate();
	if (test_device_sid & SCHID_ONE) {
		report(1, "Schid of first I/O device: 0x%08x", test_device_sid);
		return;
	}
	report(0, "No I/O device found");
}

static void test_enable(void)
{
	int cc;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	cc = css_enable(test_device_sid, IO_SCH_ISC);

	report(cc == 0, "Enable subchannel %08x", test_device_sid);
}

/*
 * test_sense
 * Pre-requisites:
 * - We need the test device as the first recognized
 *   device by the enumeration.
 */
static void test_sense(void)
{
	int ret;
	int len;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	ret = css_enable(test_device_sid, IO_SCH_ISC);
	if (ret) {
		report(0, "Could not enable the subchannel: %08x",
		       test_device_sid);
		return;
	}

	lowcore_ptr->io_int_param = 0;

	senseid = alloc_io_mem(sizeof(*senseid), 0);
	if (!senseid) {
		report(0, "Allocation of senseid");
		return;
	}

	ccw = ccw_alloc(CCW_CMD_SENSE_ID, senseid, sizeof(*senseid), CCW_F_SLI);
	if (!ccw) {
		report(0, "Allocation of CCW");
		goto error_ccw;
	}

	ret = start_ccw1_chain(test_device_sid, ccw);
	if (ret) {
		report(0, "Starting CCW chain");
		goto error;
	}

	if (wait_and_check_io_completion(test_device_sid) < 0)
		goto error;

	/* Test transfer completion */
	report_prefix_push("ssch transfer completion");

	ret = css_residual_count(test_device_sid);

	if (ret < 0) {
		report_info("no valid residual count");
	} else if (ret != 0) {
		len = sizeof(*senseid) - ret;
		if (ret && len < CSS_SENSEID_COMMON_LEN) {
			report(0, "transferred a too short length: %d", ret);
			goto error;
		} else if (ret && len)
			report_info("transferred a shorter length: %d", len);
	}

	if (senseid->reserved != 0xff) {
		report(0, "transferred garbage: 0x%02x", senseid->reserved);
		goto error;
	}

	report_prefix_pop();

	report_info("reserved 0x%02x cu_type 0x%04x cu_model 0x%02x dev_type 0x%04x dev_model 0x%02x",
		    senseid->reserved, senseid->cu_type, senseid->cu_model,
		    senseid->dev_type, senseid->dev_model);

	report(senseid->cu_type == cu_type, "cu_type expected 0x%04x got 0x%04x",
	       (uint16_t)cu_type, senseid->cu_type);

error:
	free_io_mem(ccw, sizeof(*ccw));
error_ccw:
	free_io_mem(senseid, sizeof(*senseid));
}

static void css_init(void)
{
	assert(register_io_int_func(css_irq_io) == 0);
	lowcore_ptr->io_int_param = 0;

	report(get_chsc_scsc(), "Store Channel Characteristics");
}

static void test_schm(void)
{
	if (css_test_general_feature(CSSC_EXTENDED_MEASUREMENT_BLOCK))
		report_info("Extended measurement block available");

	/* bits 59-63 of MB address must be 0  if MBU is defined */
	report_prefix_push("Unaligned operand");
	expect_pgm_int();
	schm((void *)0x01, SCHM_MBU);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
	report_prefix_pop();

	/* bits 36-61 of register 1 (flags) must be 0 */
	report_prefix_push("Bad flags");
	expect_pgm_int();
	schm(NULL, 0xfffffffc);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
	report_prefix_pop();

	/* SCHM is a privilege operation */
	report_prefix_push("Privilege");
	enter_pstate();
	expect_pgm_int();
	schm(NULL, SCHM_MBU);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	/* Normal operation */
	report_prefix_push("Normal operation");
	schm(NULL, SCHM_MBU);
	report(1, "SCHM call without address");
	report_prefix_pop();
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	/* The css_init test is needed to initialize the CSS Characteristics */
	{ "initialize CSS (chsc)", css_init },
	{ "enumerate (stsch)", test_enumerate },
	{ "enable (msch)", test_enable },
	{ "sense (ssch/tsch)", test_sense },
	{ "measurement block (schm)", test_schm },
	{ NULL, NULL }
};

int main(int argc, char *argv[])
{
	int i;

	report_prefix_push("Channel Subsystem");
	enable_io_isc(0x80 >> IO_SCH_ISC);
	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}
	report_prefix_pop();

	return report_summary();
}
