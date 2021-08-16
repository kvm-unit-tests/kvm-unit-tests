/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests SIE diagnose intercepts.
 * Mainly used as a template for SIE tests.
 *
 * Copyright 2021 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/arch_def.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <alloc_page.h>
#include <vmalloc.h>
#include <asm/facility.h>
#include <mmu.h>
#include <sclp.h>
#include <sie.h>

static u8 *guest;
static u8 *guest_instr;
static struct vm vm;

static void test_diag(u32 instr)
{
	vm.sblk->gpsw.addr = PAGE_SIZE * 2;
	vm.sblk->gpsw.mask = PSW_MASK_64;

	memset(guest_instr, 0, PAGE_SIZE);
	memcpy(guest_instr, &instr, 4);
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_INST &&
	       vm.sblk->ipa == instr >> 16 && vm.sblk->ipb == instr << 16,
	       "Intercept data");
}

static struct {
	const char *name;
	u32 instr;
} tests[] = {
	{ "10", 0x83020010 },
	{ "44", 0x83020044 },
	{ "9c", 0x8302009c },
	{ NULL, 0 }
};

static void test_diags(void)
{
	int i;

	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		test_diag(tests[i].instr);
		report_prefix_pop();
	}
}

static void setup_guest(void)
{
	setup_vm();

	/* Allocate 1MB as guest memory */
	guest = alloc_pages(8);
	/* The first two pages are the lowcore */
	guest_instr = guest + PAGE_SIZE * 2;

	sie_guest_create(&vm, (uint64_t)guest, HPAGE_SIZE);
}

int main(void)
{
	report_prefix_push("sie");
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto done;
	}

	setup_guest();
	test_diags();
	sie_guest_destroy(&vm);

done:
	report_prefix_pop();
	return report_summary();
}
