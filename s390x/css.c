/*
 * Channel Subsystem tests
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */

#include <libcflat.h>
#include <alloc_phys.h>
#include <asm/page.h>
#include <string.h>
#include <interrupt.h>
#include <asm/arch_def.h>

#include <css.h>

#define DEFAULT_CU_TYPE		0x3832 /* virtio-ccw */
static unsigned long cu_type = DEFAULT_CU_TYPE;

static int test_device_sid;
static struct senseid senseid;

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

	ret = register_io_int_func(css_irq_io);
	if (ret) {
		report(0, "Could not register IRQ handler");
		return;
	}

	lowcore_ptr->io_int_param = 0;

	memset(&senseid, 0, sizeof(senseid));
	ret = start_single_ccw(test_device_sid, CCW_CMD_SENSE_ID,
			       &senseid, sizeof(senseid), CCW_F_SLI);
	if (ret)
		goto error;

	if (wait_and_check_io_completion(test_device_sid) < 0)
		goto error;

	/* Test transfer completion */
	report_prefix_push("ssch transfer completion");

	ret = css_residual_count(test_device_sid);

	if (ret < 0) {
		report_info("no valid residual count");
	} else if (ret != 0) {
		len = sizeof(senseid) - ret;
		if (ret && len < CSS_SENSEID_COMMON_LEN) {
			report(0, "transferred a too short length: %d", ret);
			goto error;
		} else if (ret && len)
			report_info("transferred a shorter length: %d", len);
	}

	if (senseid.reserved != 0xff) {
		report(0, "transferred garbage: 0x%02x", senseid.reserved);
		goto error;
	}

	report_prefix_pop();

	report_info("reserved 0x%02x cu_type 0x%04x cu_model 0x%02x dev_type 0x%04x dev_model 0x%02x",
		    senseid.reserved, senseid.cu_type, senseid.cu_model,
		    senseid.dev_type, senseid.dev_model);

	report(senseid.cu_type == cu_type, "cu_type expected 0x%04x got 0x%04x",
	       (uint16_t) cu_type, senseid.cu_type);

error:
	unregister_io_int_func(css_irq_io);
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "enumerate (stsch)", test_enumerate },
	{ "enable (msch)", test_enable },
	{ "sense (ssch/tsch)", test_sense },
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
