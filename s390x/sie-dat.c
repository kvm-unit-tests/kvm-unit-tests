/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests SIE with paging.
 *
 * Copyright 2023 IBM Corp.
 *
 * Authors:
 *    Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <vmalloc.h>
#include <asm/pgtable.h>
#include <mmu.h>
#include <asm/page.h>
#include <asm/interrupt.h>
#include <alloc_page.h>
#include <sclp.h>
#include <sie.h>
#include <snippet.h>
#include "snippets/c/sie-dat.h"

static struct vm vm;
static pgd_t *guest_root;

static void test_sie_dat(void)
{
	uint64_t test_page_gpa, test_page_hpa;
	uint8_t *test_page_hva, expected_val;
	bool contents_match;
	uint8_t r1;

	/* guest will tell us the guest physical address of the test buffer */
	sie(&vm);
	assert(vm.sblk->icptcode == ICPT_INST &&
	       (vm.sblk->ipa & 0xff00) == 0x8300 && vm.sblk->ipb == 0x9c0000);

	r1 = (vm.sblk->ipa & 0xf0) >> 4;
	test_page_gpa = vm.save_area.guest.grs[r1];
	test_page_hpa = virt_to_pte_phys(guest_root, (void*)test_page_gpa);
	test_page_hva = __va(test_page_hpa);
	report_info("test buffer gpa=0x%lx hva=%p", test_page_gpa, test_page_hva);

	/* guest will now write to the test buffer and we verify the contents */
	sie(&vm);
	assert(vm.sblk->icptcode == ICPT_INST &&
	       vm.sblk->ipa == 0x8300 && vm.sblk->ipb == 0x440000);

	contents_match = true;
	for (unsigned int i = 0; i < GUEST_TEST_PAGE_COUNT; i++) {
		expected_val = 42 + i;
		if (test_page_hva[i * PAGE_SIZE] != expected_val) {
			report_fail("page %u mismatch actual_val=%x expected_val=%x",
				    i, test_page_hva[i], expected_val);
			contents_match = false;
		}
	}
	report(contents_match, "test buffer contents match");

	/* the guest will now write to an unmapped address and we check that this causes a segment translation exception */
	report_prefix_push("guest write to unmapped");
	expect_pgm_int();
	sie(&vm);
	check_pgm_int_code(PGM_INT_CODE_SEGMENT_TRANSLATION);
	report((lowcore.trans_exc_id & PAGE_MASK) == (GUEST_TOTAL_PAGE_COUNT * PAGE_SIZE), "TEID address match");
	report_prefix_pop();
}

static void setup_guest(void)
{
	extern const char SNIPPET_NAME_START(c, sie_dat)[];
	extern const char SNIPPET_NAME_END(c, sie_dat)[];
	uint64_t guest_max_addr;
	pgd_t *root;

	setup_vm();
	root = (pgd_t *)(stctg(1) & PAGE_MASK);

	snippet_setup_guest(&vm, false);

	/* allocate a region-1 table */
	guest_root = pgd_alloc_one();

	/* map guest memory 1:1 */
	guest_max_addr = GUEST_TOTAL_PAGE_COUNT * PAGE_SIZE;
	for (uint64_t i = 0; i < guest_max_addr; i += PAGE_SIZE)
		install_page(guest_root, virt_to_pte_phys(root, vm.guest_mem + i), (void *)i);

	/* set up storage limit supression - leave mso and msl intact they are ignored anyways */
	vm.sblk->cpuflags |= CPUSTAT_SM;

	/* set up the guest asce */
	vm.save_area.guest.asce = __pa(guest_root) | ASCE_DT_REGION1 | REGION_TABLE_LENGTH;

	snippet_init(&vm, SNIPPET_NAME_START(c, sie_dat),
		     SNIPPET_LEN(c, sie_dat), SNIPPET_UNPACK_OFF);
}

int main(void)
{
	report_prefix_push("sie-dat");
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto done;
	}

	setup_guest();
	test_sie_dat();
	sie_guest_destroy(&vm);

done:
	report_prefix_pop();
	return report_summary();

}
