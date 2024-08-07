#ifndef _ASMARM_PGTABLE_H_
#define _ASMARM_PGTABLE_H_
/*
 * Adapted from arch/arm/include/asm/pgtable.h
 *              arch/arm/include/asm/pgtable-3level.h
 *              arch/arm/include/asm/pgalloc.h
 *
 * Note: some Linux function APIs have been modified. Nothing crazy,
 *       but if a function took, for example, an mm_struct, then
 *       that was either removed or replaced.
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#include <alloc.h>
#include <alloc_page.h>
#include <asm/setup.h>

/*
 * We can convert va <=> pa page table addresses with simple casts
 * because we always allocate their pages with alloc_page(), and
 * alloc_page() always returns identity mapped pages.
 */
#include <linux/compiler.h>

#define pgtable_va(x)		((void *)(unsigned long)(x))
#define pgtable_pa(x)		((unsigned long)(x))

#define pgd_none(pgd)		(!pgd_val(pgd))
#define pmd_none(pmd)		(!pmd_val(pmd))
#define pte_none(pte)		(!pte_val(pte))

#define pgd_valid(pgd)		(pgd_val(pgd) & PGD_VALID)
#define pmd_valid(pmd)		(pmd_val(pmd) & PMD_SECT_VALID)
#define pte_valid(pte)		(pte_val(pte) & L_PTE_VALID)

#define pmd_huge(pmd)	\
	((pmd_val(pmd) & PMD_TYPE_MASK) == PMD_TYPE_SECT)

#define pgd_index(addr) \
	(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_offset(pgtable, addr) ((pgtable) + pgd_index(addr))

#define pgd_free(pgd) free(pgd)
static inline pgd_t *pgd_alloc(void)
{
	pgd_t *pgd = memalign(L1_CACHE_BYTES, PTRS_PER_PGD * sizeof(pgd_t));
	memset(pgd, 0, PTRS_PER_PGD * sizeof(pgd_t));
	return pgd;
}

static inline pmd_t *pgd_page_vaddr(pgd_t pgd)
{
	return pgtable_va(pgd_val(pgd) & PHYS_MASK & (s32)PAGE_MASK);
}

/* For compatibility with arm64 page tables */
#define pud_valid(pud)		pgd_valid(pud)
#define pud_offset(pgd, addr)	((pud_t *)pgd)
#define pud_free(pud)
#define pud_alloc(pgd, addr)	pud_offset(pgd, addr)

#define pmd_index(addr) \
	(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pmd_offset(pgd, addr) \
	(pgd_page_vaddr(*(pgd)) + pmd_index(addr))

#define pmd_free(pmd) free_page(pmd)
static inline pmd_t *pmd_alloc_one(void)
{
	assert(PTRS_PER_PMD * sizeof(pmd_t) == PAGE_SIZE);
	pmd_t *pmd = alloc_page();
	return pmd;
}
static inline pmd_t *pmd_alloc(pgd_t *pgd, unsigned long addr)
{
	if (pgd_none(*pgd)) {
		pgd_t entry;
		pgd_val(entry) = pgtable_pa(pmd_alloc_one()) | PMD_TYPE_TABLE;
		WRITE_ONCE(*pgd, entry);
	}
	return pmd_offset(pgd, addr);
}

static inline pte_t *pmd_page_vaddr(pmd_t pmd)
{
	return pgtable_va(pmd_val(pmd) & PHYS_MASK & (s32)PAGE_MASK);
}

#define pte_index(addr) \
	(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset(pmd, addr) \
	(pmd_page_vaddr(*(pmd)) + pte_index(addr))

#define pte_free(pte) free_page(pte)
static inline pte_t *pte_alloc_one(void)
{
	assert(PTRS_PER_PTE * sizeof(pte_t) == PAGE_SIZE);
	pte_t *pte = alloc_page();
	return pte;
}
static inline pte_t *pte_alloc(pmd_t *pmd, unsigned long addr)
{
	if (pmd_none(*pmd)) {
		pmd_t entry;
		pmd_val(entry) = pgtable_pa(pte_alloc_one()) | PMD_TYPE_TABLE;
		WRITE_ONCE(*pmd, entry);
	}
	return pte_offset(pmd, addr);
}

#endif /* _ASMARM_PGTABLE_H_ */
