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
static volatile int ud;
static volatile int isize;

static void handle_ud(struct ex_regs *regs)
{
	ud = 1;
	regs->rip += isize;
}

int main(int ac, char **av)
{
	handle_exception(UD_VECTOR, handle_ud);

	/* 3-byte instructions: */
	isize = 3;

	if (this_cpu_has(X86_FEATURE_CLFLUSH)) { /* CLFLUSH */
		ud = 0;
		asm volatile("clflush (%0)" : : "b" (&target));
		report(!ud, "clflush");
	} else {
		report_skip("clflush");
	}

	if (this_cpu_has(X86_FEATURE_XMM)) { /* SSE */
		ud = 0;
		asm volatile("sfence");
		report(!ud, "sfence");
	} else {
		report_skip("sfence");
	}

	if (this_cpu_has(X86_FEATURE_XMM2)) { /* SSE2 */
		ud = 0;
		asm volatile("lfence");
		report(!ud, "lfence");
		ud = 0;
		asm volatile("mfence");
		report(!ud, "mfence");
	} else {
		report_skip("lfence");
		report_skip("mfence");
	}

	/* 4-byte instructions: */
	isize = 4;

	if (this_cpu_has(X86_FEATURE_CLFLUSHOPT)) { /* CLFLUSHOPT */
		ud = 0;
		/* clflushopt (%rbx): */
		asm volatile(".byte 0x66, 0x0f, 0xae, 0x3b" : : "b" (&target));
		report(!ud, "clflushopt");
	} else {
		report_skip("clflushopt");
	}

	if (this_cpu_has(X86_FEATURE_CLWB)) { /* CLWB */
		ud = 0;
		/* clwb (%rbx): */
		asm volatile(".byte 0x66, 0x0f, 0xae, 0x33" : : "b" (&target));
		report(!ud, "clwb");
	} else {
		report_skip("clwb");
	}

	if (this_cpu_has(X86_FEATURE_PCOMMIT)) { /* PCOMMIT */
		ud = 0;
		/* pcommit: */
		asm volatile(".byte 0x66, 0x0f, 0xae, 0xf8");
		report(!ud, "pcommit");
	} else {
		report_skip("pcommit");
	}

	return report_summary();
}
