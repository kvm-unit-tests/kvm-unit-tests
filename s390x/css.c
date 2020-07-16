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

static int test_device_sid;

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

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "enumerate (stsch)", test_enumerate },
	{ "enable (msch)", test_enable },
	{ NULL, NULL }
};

int main(int argc, char *argv[])
{
	int i;

	report_prefix_push("Channel Subsystem");
	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}
	report_prefix_pop();

	return report_summary();
}
