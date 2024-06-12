/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMARM64_PGTABLE_H_
#define _ASMARM64_PGTABLE_H_
/*
 * Copyright (C) 2024, IBM Inc, Nicholas Piggin <npiggin@gmail.com>
 *
 * Derived from Linux kernel MMU code.
 */
#include <alloc.h>
#include <alloc_page.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/pgtable-hwdef.h>

#include <linux/compiler.h>

/*
 * We can convert va <=> pa page table addresses with simple casts
 * because we always allocate their pages with alloc_page(), and
 * alloc_page() always returns identity mapped pages.
 */
#define pgtable_va(x)		((void *)(unsigned long)(x))
#define pgtable_pa(x)		((unsigned long)(x))

#define pgd_none(pgd)		(!pgd_val(pgd))
#define pud_none(pud)		(!pud_val(pud))
#define pmd_none(pmd)		(!pmd_val(pmd))
#define pte_none(pte)		(!pte_val(pte))

#define pgd_valid(pgd)		(pgd_val(pgd) & cpu_to_be64(_PAGE_VALID))
#define pud_valid(pud)		(pud_val(pud) & cpu_to_be64(_PAGE_VALID))
#define pmd_valid(pmd)		(pmd_val(pmd) & cpu_to_be64(_PAGE_VALID))
#define pte_valid(pte)		(pte_val(pte) & cpu_to_be64(_PAGE_VALID))

#define pmd_huge(pmd)		false

static inline pud_t *pgd_page_vaddr(pgd_t pgd)
{
	return pgtable_va(be64_to_cpu(pgd_val(pgd)) & PHYS_MASK & ~0xfffULL);
}

static inline pmd_t *pud_page_vaddr(pud_t pud)
{
	return pgtable_va(be64_to_cpu(pud_val(pud)) & PHYS_MASK & ~0xfffULL);
}

static inline pte_t *pmd_page_vaddr(pmd_t pmd)
{
	return pgtable_va(be64_to_cpu(pmd_val(pmd)) & PHYS_MASK & ~0xfffULL);
}

#define pgd_index(addr)		(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_offset(pt, addr)	((pt) + pgd_index(addr))
#define pud_index(addr)		(((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pud_offset(pgd, addr)	(pgd_page_vaddr(*(pgd)) + pud_index(addr))
#define pmd_index(addr)		(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pmd_offset(pud, addr)	(pud_page_vaddr(*(pud)) + pmd_index(addr))
#define pte_index(addr)		(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset(pmd, addr)	(pmd_page_vaddr(*(pmd)) + pte_index(addr))

#define pgd_free(pgd) free(pgd)
static inline pgd_t *pgd_alloc_one(void)
{
	size_t sz = PTRS_PER_PGD * sizeof(pgd_t);
	pgd_t *pgd = memalign_pages(sz, sz);
	memset(pgd, 0, sz);
	return pgd;
}

#define pud_free(pud) free(pud)
static inline pud_t *pud_alloc_one(void)
{
	size_t sz = PTRS_PER_PGD * sizeof(pud_t);
	pud_t *pud = memalign_pages(sz, sz);
	memset(pud, 0, sz);
	return pud;
}
static inline pud_t *pud_alloc(pgd_t *pgd, unsigned long addr)
{
	if (pgd_none(*pgd)) {
		pgd_t entry;
		pgd_val(entry) = cpu_to_be64(pgtable_pa(pud_alloc_one()) | _PAGE_VALID | (12 - 3) /* 4k pud page */);
		WRITE_ONCE(*pgd, entry);
	}
	return pud_offset(pgd, addr);
}

#define pmd_free(pmd) free(pmd)
static inline pmd_t *pmd_alloc_one(void)
{
	size_t sz = PTRS_PER_PMD * sizeof(pmd_t);
	pmd_t *pmd = memalign_pages(sz, sz);
	memset(pmd, 0, sz);
	return pmd;
}
static inline pmd_t *pmd_alloc(pud_t *pud, unsigned long addr)
{
	if (pud_none(*pud)) {
		pud_t entry;
		pud_val(entry) = cpu_to_be64(pgtable_pa(pmd_alloc_one()) | _PAGE_VALID | (12 - 3) /* 4k pmd page */);
		WRITE_ONCE(*pud, entry);
	}
	return pmd_offset(pud, addr);
}

#define pte_free(pte) free(pte)
static inline pte_t *pte_alloc_one(void)
{
	size_t sz = PTRS_PER_PTE * sizeof(pte_t);
	pte_t *pte = memalign_pages(sz, sz);
	memset(pte, 0, sz);
	return pte;
}
static inline pte_t *pte_alloc(pmd_t *pmd, unsigned long addr)
{
	if (pmd_none(*pmd)) {
		pmd_t entry;
		pmd_val(entry) = cpu_to_be64(pgtable_pa(pte_alloc_one()) | _PAGE_VALID | (21 - PAGE_SHIFT) /* 4k/256B pte page */);
		WRITE_ONCE(*pmd, entry);
	}
	return pte_offset(pmd, addr);
}

#endif /* _ASMPPC64_PGTABLE_H_ */
