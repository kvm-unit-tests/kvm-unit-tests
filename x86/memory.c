/*
 * Test for x86 cache and memory instructions
 *
 * Copyright (c) 2015 Red Hat Inc
 *
 * Authors:
 *  Eduardo Habkost <ehabkost@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "libcflat.h"
#include "desc.h"
#include "processor.h"

static long target;

int main(int ac, char **av)
{
	if (this_cpu_has(X86_FEATURE_CLFLUSH))
		asm_safe_report("clflush (%0)", "b" (&target));
	else
		report_skip("clflush");

	if (this_cpu_has(X86_FEATURE_XMM))
		asm_safe_report("sfence");
	else
		report_skip("sfence");

	if (this_cpu_has(X86_FEATURE_XMM2)) {
		asm_safe_report("lfence");
		asm_safe_report("mfence");
	} else {
		report_skip("lfence");
		report_skip("mfence");
	}

	if (this_cpu_has(X86_FEATURE_CLFLUSHOPT)) {
		/* clflushopt (%rbx): */
		asm_safe_report(".byte 0x66, 0x0f, 0xae, 0x3b", "b" (&target));
	} else {
		report_skip("clflushopt");
	}

	if (this_cpu_has(X86_FEATURE_CLWB)) {
		/* clwb (%rbx): */
		asm_safe_report(".byte 0x66, 0x0f, 0xae, 0x33", "b" (&target));
	} else {
		report_skip("clwb");
	}

	if (this_cpu_has(X86_FEATURE_PCOMMIT)) { /* PCOMMIT */
		/* pcommit: */
		asm_safe_report(".byte 0x66, 0x0f, 0xae, 0xf8");
	} else {
		report_skip("pcommit");
	}

	return report_summary();
}
