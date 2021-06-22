/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x MMU
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 */

#include <libcflat.h>
#include <asm/pgtable.h>
#include <asm/arch_def.h>
#include <asm/barrier.h>
#include <vmalloc.h>
#include "mmu.h"

/*
 * The naming convention used here is the same as used in the Linux kernel;
 * this is the correspondence between the s390x architectural names and the
 * Linux ones:
 *
 * pgd - region 1 table entry
 * p4d - region 2 table entry
 * pud - region 3 table entry
 * pmd - segment table entry
 * pte - page table entry
 */

static pgd_t *table_root;

void configure_dat(int enable)
{
	uint64_t mask;

	if (enable)
		mask = extract_psw_mask() | PSW_MASK_DAT;
	else
		mask = extract_psw_mask() & ~PSW_MASK_DAT;

	load_psw_mask(mask);
}

static void mmu_enable(pgd_t *pgtable)
{
	struct lowcore *lc = NULL;
	const uint64_t asce = __pa(pgtable) | ASCE_DT_REGION1 |
			      REGION_TABLE_LENGTH;

	/* set primary asce */
	lctlg(1, asce);
	assert(stctg(1) == asce);

	/* enable dat (primary == 0 set as default) */
	configure_dat(1);

	/* we can now also use DAT unconditionally in our PGM handler */
	lc->pgm_new_psw.mask |= PSW_MASK_DAT;
}

/*
 * Get the pud (region 3) DAT table entry for the given address and root,
 * allocating it if necessary
 */
static inline pud_t *get_pud(pgd_t *pgtable, uintptr_t vaddr)
{
	pgd_t *pgd = pgd_offset(pgtable, vaddr);
	p4d_t *p4d = p4d_alloc(pgd, vaddr);
	pud_t *pud = pud_alloc(p4d, vaddr);

	return pud;
}

/*
 * Get the pmd (segment) DAT table entry for the given address and pud,
 * allocating it if necessary.
 * The pud must not be huge.
 */
static inline pmd_t *get_pmd(pud_t *pud, uintptr_t vaddr)
{
	pmd_t *pmd;

	assert(!pud_huge(*pud));
	pmd = pmd_alloc(pud, vaddr);
	return pmd;
}

/*
 * Get the pte (page) DAT table entry for the given address and pmd,
 * allocating it if necessary.
 * The pmd must not be large.
 */
static inline pte_t *get_pte(pmd_t *pmd, uintptr_t vaddr)
{
	pte_t *pte;

	assert(!pmd_large(*pmd));
	pte = pte_alloc(pmd, vaddr);
	return pte;
}

/*
 * Splits a large pmd (segment) DAT table entry into equivalent 4kB small
 * pages.
 * @pmd The pmd to split, it must be large.
 * @va the virtual address corresponding to this pmd.
 */
static void split_pmd(pmd_t *pmd, uintptr_t va)
{
	phys_addr_t pa = pmd_val(*pmd) & SEGMENT_ENTRY_SFAA;
	unsigned long i, prot;
	pte_t *pte;

	assert(pmd_large(*pmd));
	pte = alloc_pages(PAGE_TABLE_ORDER);
	prot = pmd_val(*pmd) & (SEGMENT_ENTRY_IEP | SEGMENT_ENTRY_P);
	for (i = 0; i < PAGE_TABLE_ENTRIES; i++)
		pte_val(pte[i]) =  pa | PAGE_SIZE * i | prot;
	idte_pmdp(va, &pmd_val(*pmd));
	pmd_val(*pmd) = __pa(pte) | SEGMENT_ENTRY_TT_SEGMENT;

}

/*
 * Splits a huge pud (region 3) DAT table entry into equivalent 1MB large
 * pages.
 * @pud The pud to split, it must be huge.
 * @va the virtual address corresponding to this pud.
 */
static void split_pud(pud_t *pud, uintptr_t va)
{
	phys_addr_t pa = pud_val(*pud) & REGION3_ENTRY_RFAA;
	unsigned long i, prot;
	pmd_t *pmd;

	assert(pud_huge(*pud));
	pmd = alloc_pages(SEGMENT_TABLE_ORDER);
	prot = pud_val(*pud) & (REGION3_ENTRY_IEP | REGION_ENTRY_P);
	for (i = 0; i < SEGMENT_TABLE_ENTRIES; i++)
		pmd_val(pmd[i]) =  pa | SZ_1M * i | prot | SEGMENT_ENTRY_FC | SEGMENT_ENTRY_TT_SEGMENT;
	idte_pudp(va, &pud_val(*pud));
	pud_val(*pud) = __pa(pmd) | REGION_ENTRY_TT_REGION3 | REGION_TABLE_LENGTH;
}

void *get_dat_entry(pgd_t *pgtable, void *vaddr, enum pgt_level level)
{
	uintptr_t va = (uintptr_t)vaddr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	assert(level && (level <= 5));
	pgd = pgd_offset(pgtable, va);
	if (level == pgtable_level_pgd)
		return pgd;
	p4d = p4d_alloc(pgd, va);
	if (level == pgtable_level_p4d)
		return p4d;
	pud = pud_alloc(p4d, va);

	if (level == pgtable_level_pud)
		return pud;
	if (!pud_none(*pud) && pud_huge(*pud))
		split_pud(pud, va);
	pmd = get_pmd(pud, va);
	if (level == pgtable_level_pmd)
		return pmd;
	if (!pmd_none(*pmd) && pmd_large(*pmd))
		split_pmd(pmd, va);
	return get_pte(pmd, va);
}

void *split_page(pgd_t *pgtable, void *vaddr, enum pgt_level level)
{
	assert((level >= 3) && (level <= 5));
	return get_dat_entry(pgtable ? pgtable : table_root, vaddr, level);
}

phys_addr_t virt_to_pte_phys(pgd_t *pgtable, void *vaddr)
{
	uintptr_t va = (uintptr_t)vaddr;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pud = get_pud(pgtable, va);
	if (pud_huge(*pud))
		return (pud_val(*pud) & REGION3_ENTRY_RFAA) | (va & ~REGION3_ENTRY_RFAA);
	pmd = get_pmd(pud, va);
	if (pmd_large(*pmd))
		return (pmd_val(*pmd) & SEGMENT_ENTRY_SFAA) | (va & ~SEGMENT_ENTRY_SFAA);
	pte = get_pte(pmd, va);
	return (pte_val(*pte) & PAGE_MASK) | (va & ~PAGE_MASK);
}

/*
 * Get the DAT table entry of the given level for the given address,
 * splitting if necessary. If the entry was not invalid, invalidate it, and
 * return the pointer to the entry and, if requested, its old value.
 * @pgtable root of the page tables
 * @vaddr virtual address
 * @level 3 (for 2GB pud), 4 (for 1MB pmd) or 5 (for 4kB pages)
 * @old if not NULL, will be written with the old value of the DAT table
 * entry before invalidation
 */
static void *dat_get_and_invalidate(pgd_t *pgtable, void *vaddr, enum pgt_level level, unsigned long *old)
{
	unsigned long va = (unsigned long)vaddr;
	void *ptr;

	ptr = get_dat_entry(pgtable, vaddr, level);
	if (old)
		*old = *(unsigned long *)ptr;
	if ((level == pgtable_level_pgd) && !pgd_none(*(pgd_t *)ptr))
		idte_pgdp(va, ptr);
	else if ((level == pgtable_level_p4d) && !p4d_none(*(p4d_t *)ptr))
		idte_p4dp(va, ptr);
	else if ((level == pgtable_level_pud) && !pud_none(*(pud_t *)ptr))
		idte_pudp(va, ptr);
	else if ((level == pgtable_level_pmd) && !pmd_none(*(pmd_t *)ptr))
		idte_pmdp(va, ptr);
	else if (!pte_none(*(pte_t *)ptr))
		ipte(va, ptr);
	return ptr;
}

static void cleanup_pmd(pmd_t *pmd)
{
	/* was invalid or large, nothing to do */
	if (pmd_none(*pmd) || pmd_large(*pmd))
		return;
	/* was not large, free the corresponding page table */
	free_pages((void *)(pmd_val(*pmd) & PAGE_MASK));
}

static void cleanup_pud(pud_t *pud)
{
	unsigned long i;
	pmd_t *pmd;

	/* was invalid or large, nothing to do */
	if (pud_none(*pud) || pud_huge(*pud))
		return;
	/* recursively clean up all pmds if needed */
	pmd = (pmd_t *)(pud_val(*pud) & PAGE_MASK);
	for (i = 0; i < SEGMENT_TABLE_ENTRIES; i++)
		cleanup_pmd(pmd + i);
	/* free the corresponding segment table */
	free_pages(pmd);
}

/*
 * Set the DAT entry for the given level of the given virtual address. If a
 * mapping already existed, it is overwritten. If an existing mapping with
 * smaller pages existed, all the lower tables are freed.
 * Returns the pointer to the DAT table entry.
 * @pgtable root of the page tables
 * @val the new value for the DAT table entry
 * @vaddr the virtual address
 * @level 3 for pud (region 3), 4 for pmd (segment) and 5 for pte (pages)
 */
static void *set_dat_entry(pgd_t *pgtable, unsigned long val, void *vaddr, enum pgt_level level)
{
	unsigned long old, *res;

	res = dat_get_and_invalidate(pgtable, vaddr, level, &old);
	if (level == pgtable_level_pmd)
		cleanup_pmd((pmd_t *)&old);
	if (level == pgtable_level_pud)
		cleanup_pud((pud_t *)&old);
	*res = val;
	return res;
}

pteval_t *install_page(pgd_t *pgtable, phys_addr_t phys, void *vaddr)
{
	assert(IS_ALIGNED(phys, PAGE_SIZE));
	assert(IS_ALIGNED((uintptr_t)vaddr, PAGE_SIZE));
	return set_dat_entry(pgtable, phys, vaddr, pgtable_level_pte);
}

pmdval_t *install_large_page(pgd_t *pgtable, phys_addr_t phys, void *vaddr)
{
	assert(IS_ALIGNED(phys, SZ_1M));
	assert(IS_ALIGNED((uintptr_t)vaddr, SZ_1M));
	return set_dat_entry(pgtable, phys | SEGMENT_ENTRY_FC, vaddr, pgtable_level_pmd);
}

pudval_t *install_huge_page(pgd_t *pgtable, phys_addr_t phys, void *vaddr)
{
	assert(IS_ALIGNED(phys, SZ_2G));
	assert(IS_ALIGNED((uintptr_t)vaddr, SZ_2G));
	return set_dat_entry(pgtable, phys | REGION3_ENTRY_FC | REGION_ENTRY_TT_REGION3, vaddr, pgtable_level_pud);
}

void protect_dat_entry(void *vaddr, unsigned long prot, enum pgt_level level)
{
	unsigned long old, *ptr;

	ptr = dat_get_and_invalidate(table_root, vaddr, level, &old);
	*ptr = old | prot;
}

void unprotect_dat_entry(void *vaddr, unsigned long prot, enum pgt_level level)
{
	unsigned long old, *ptr;

	ptr = dat_get_and_invalidate(table_root, vaddr, level, &old);
	*ptr = old & ~prot;
}

void protect_range(void *start, unsigned long len, unsigned long prot)
{
	uintptr_t curr = (uintptr_t)start & PAGE_MASK;

	len &= PAGE_MASK;
	for (; len; len -= PAGE_SIZE, curr += PAGE_SIZE)
		protect_dat_entry((void *)curr, prot, 5);
}

void unprotect_range(void *start, unsigned long len, unsigned long prot)
{
	uintptr_t curr = (uintptr_t)start & PAGE_MASK;

	len &= PAGE_MASK;
	for (; len; len -= PAGE_SIZE, curr += PAGE_SIZE)
		unprotect_dat_entry((void *)curr, prot, 5);
}

static void setup_identity(pgd_t *pgtable, phys_addr_t start_addr,
			   phys_addr_t end_addr)
{
	phys_addr_t cur;

	start_addr &= PAGE_MASK;
	for (cur = start_addr; true; cur += PAGE_SIZE) {
		if (start_addr < end_addr && cur >= end_addr)
			break;
		if (start_addr > end_addr && cur <= end_addr)
			break;
		install_page(pgtable, cur, __va(cur));
	}
}

void *setup_mmu(phys_addr_t phys_end, void *unused)
{
	pgd_t *page_root;

	/* allocate a region-1 table */
	page_root = pgd_alloc_one();

	/* map all physical memory 1:1 */
	setup_identity(page_root, 0, phys_end);

	/* generate 128MB of invalid adresses at the end (for testing PGM) */
	init_alloc_vpage((void *) -(1UL << 27));
	setup_identity(page_root, -(1UL << 27), 0);

	/* finally enable DAT with the new table */
	mmu_enable(page_root);
	table_root = page_root;
	return page_root;
}
