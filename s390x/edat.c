/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * EDAT test.
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *	Claudio Imbrenda <imbrenda@linux.ibm.com>
 */
#include <libcflat.h>
#include <vmalloc.h>
#include <asm/facility.h>
#include <asm/interrupt.h>
#include <mmu.h>
#include <asm/pgtable.h>
#include <asm-generic/barrier.h>

#define PGD_PAGE_SHIFT (REGION1_SHIFT - PAGE_SHIFT)

#define LC_SIZE	(2 * PAGE_SIZE)
#define VIRT(x)	((void *)((unsigned long)(x) + (unsigned long)mem))

static uint8_t prefix_buf[LC_SIZE] __attribute__((aligned(LC_SIZE)));
static unsigned int tmp[1024] __attribute__((aligned(PAGE_SIZE)));
static void *root, *mem, *m;
static struct lowcore *lc;
volatile unsigned int *p;

/*
 * Check if a non-access-list protection exception happened for the given
 * address, in the primary address space.
 */
static bool check_pgm_prot(void *ptr)
{
	union teid teid;

	if (lc->pgm_int_code != PGM_INT_CODE_PROTECTION)
		return false;

	teid.val = lc->trans_exc_id;

	/*
	 * depending on the presence of the ESOP feature, the rest of the
	 * field might or might not be meaningful when the m field is 0.
	 */
	if (!teid.m)
		return true;
	return (!teid.acc_list_prot && !teid.asce_id &&
		(teid.addr == ((unsigned long)ptr >> PAGE_SHIFT)));
}

static void test_dat(void)
{
	report_prefix_push("edat off");
	/* disable EDAT */
	ctl_clear_bit(0, CTL0_EDAT);

	/* Check some basics */
	p[0] = 42;
	report(p[0] == 42, "pte, r/w");
	p[0] = 0;

	/* Write protect the page and try to write, expect a fault */
	protect_page(m, PAGE_ENTRY_P);
	expect_pgm_int();
	p[0] = 42;
	unprotect_page(m, PAGE_ENTRY_P);
	report(!p[0] && check_pgm_prot(m), "pte, ro");

	/*
	 * The FC bit (for large pages) should be ignored because EDAT is
	 * off. We set a value and then we try to read it back again after
	 * setting the FC bit. This way we can check if large pages were
	 * erroneously enabled despite EDAT being off.
	 */
	p[0] = 42;
	protect_dat_entry(m, SEGMENT_ENTRY_FC, pgtable_level_pmd);
	report(p[0] == 42, "pmd, fc=1, r/w");
	unprotect_dat_entry(m, SEGMENT_ENTRY_FC, pgtable_level_pmd);
	p[0] = 0;

	/*
	 * Segment protection should work even with EDAT off, try to write
	 * anyway and expect a fault
	 */
	protect_dat_entry(m, SEGMENT_ENTRY_P, pgtable_level_pmd);
	expect_pgm_int();
	p[0] = 42;
	report(!p[0] && check_pgm_prot(m), "pmd, ro");
	unprotect_dat_entry(m, SEGMENT_ENTRY_P, pgtable_level_pmd);

	/* The FC bit should be ignored because EDAT is off, like above */
	p[0] = 42;
	protect_dat_entry(m, REGION3_ENTRY_FC, pgtable_level_pud);
	report(p[0] == 42, "pud, fc=1, r/w");
	unprotect_dat_entry(m, REGION3_ENTRY_FC, pgtable_level_pud);
	p[0] = 0;

	/*
	 * Region1/2/3 protection should not work, because EDAT is off.
	 * Protect the various region1/2/3 entries and write, expect the
	 * write to be successful.
	 */
	protect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pud);
	p[0] = 42;
	report(p[0] == 42, "pud, ro");
	unprotect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pud);
	p[0] = 0;

	protect_dat_entry(m, REGION_ENTRY_P, pgtable_level_p4d);
	p[0] = 42;
	report(p[0] == 42, "p4d, ro");
	unprotect_dat_entry(m, REGION_ENTRY_P, pgtable_level_p4d);
	p[0] = 0;

	protect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pgd);
	p[0] = 42;
	report(p[0] == 42, "pgd, ro");
	unprotect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pgd);
	p[0] = 0;

	report_prefix_pop();
}

static void test_edat1(void)
{
	report_prefix_push("edat1");
	/* Enable EDAT */
	ctl_set_bit(0, CTL0_EDAT);
	p[0] = 0;

	/*
	 * Segment protection should work normally, try to write and expect
	 * a fault.
	 */
	expect_pgm_int();
	protect_dat_entry(m, SEGMENT_ENTRY_P, pgtable_level_pmd);
	p[0] = 42;
	report(!p[0] && check_pgm_prot(m), "pmd, ro");
	unprotect_dat_entry(m, SEGMENT_ENTRY_P, pgtable_level_pmd);

	/*
	 * Region1/2/3 protection should work now, because EDAT is on. Try
	 * to write anyway and expect a fault.
	 */
	expect_pgm_int();
	protect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pud);
	p[0] = 42;
	report(!p[0] && check_pgm_prot(m), "pud, ro");
	unprotect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pud);

	expect_pgm_int();
	protect_dat_entry(m, REGION_ENTRY_P, pgtable_level_p4d);
	p[0] = 42;
	report(!p[0] && check_pgm_prot(m), "p4d, ro");
	unprotect_dat_entry(m, REGION_ENTRY_P, pgtable_level_p4d);

	expect_pgm_int();
	protect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pgd);
	p[0] = 42;
	report(!p[0] && check_pgm_prot(m), "pgd, ro");
	unprotect_dat_entry(m, REGION_ENTRY_P, pgtable_level_pgd);

	/* Large pages should work */
	p[0] = 42;
	install_large_page(root, 0, mem);
	report(p[0] == 42, "pmd, large");

	/*
	 * Prefixing should not work with large pages. Since the lower
	 * addresses are mapped with small pages, which are subject to
	 * prefixing, and the pages mapped with large pages are not subject
	 * to prefixing, this is the resulting scenario:
	 *
	 * virtual 0 = real 0 -> absolute prefix_buf
	 * virtual prefix_buf = real prefix_buf -> absolute 0
	 * VIRT(0) -> absolute 0
	 * VIRT(prefix_buf) -> absolute prefix_buf
	 *
	 * The testcase checks if the memory at virtual 0 has the same
	 * content as the memory at VIRT(prefix_buf) and the memory at
	 * VIRT(0) has the same content as the memory at virtual prefix_buf.
	 * If prefixing is erroneously applied for large pages, the testcase
	 * will therefore fail.
	 */
	report(!memcmp(0, VIRT(prefix_buf), LC_SIZE) &&
		!memcmp(prefix_buf, VIRT(0), LC_SIZE),
		"pmd, large, prefixing");

	report_prefix_pop();
}

static void test_edat2(void)
{
	report_prefix_push("edat2");
	p[0] = 42;

	/* Huge pages should work */
	install_huge_page(root, 0, mem);
	report(p[0] == 42, "pud, huge");

	/* Prefixing should not work with huge pages, just like large pages */
	report(!memcmp(0, VIRT(prefix_buf), LC_SIZE) &&
		!memcmp(prefix_buf, VIRT(0), LC_SIZE),
		"pmd, large, prefixing");

	report_prefix_pop();
}

static unsigned int setup(void)
{
	bool has_edat1 = test_facility(8);
	bool has_edat2 = test_facility(78);
	unsigned long pa, va;

	if (has_edat2 && !has_edat1)
		report_abort("EDAT2 available, but EDAT1 not available");

	/* Setup DAT 1:1 mapping and memory management */
	setup_vm();
	root = (void *)(stctg(1) & PAGE_MASK);

	/*
	 * Get a pgd worth of virtual memory, so we can test things later
	 * without interfering with the test code or the interrupt handler
	 */
	mem = alloc_vpages_aligned(BIT_ULL(PGD_PAGE_SHIFT), PGD_PAGE_SHIFT);
	assert(mem);
	va = (unsigned long)mem;

	/* Map the first 1GB of real memory */
	for (pa = 0; pa < SZ_1G; pa += PAGE_SIZE, va += PAGE_SIZE)
		install_page(root, pa, (void *)va);

	/*
	 * Move the lowcore to a known non-zero location. This is needed
	 * later to check whether prefixing is working with large pages.
	 */
	assert((unsigned long)&prefix_buf < SZ_2G);
	memcpy(prefix_buf, 0, LC_SIZE);
	set_prefix((uint32_t)(uintptr_t)prefix_buf);
	/* Clear the old copy */
	memset(prefix_buf, 0, LC_SIZE);

	/* m will point to tmp through the new virtual mapping */
	m = VIRT(&tmp);
	/* p is the same as m but volatile */
	p = (volatile unsigned int *)m;

	return has_edat1 + has_edat2;
}

int main(void)
{
	unsigned int edat;

	report_prefix_push("edat");
	edat = setup();

	test_dat();

	if (edat)
		test_edat1();
	else
		report_skip("EDAT not available");

	if (edat >= 2)
		test_edat2();
	else
		report_skip("EDAT2 not available");

	report_prefix_pop();
	return report_summary();
}
