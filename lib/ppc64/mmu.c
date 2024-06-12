// SPDX-License-Identifier: GPL-2.0-only
/*
 * Radix MMU support
 *
 * Copyright (C) 2024, IBM Inc, Nicholas Piggin <npiggin@gmail.com>
 *
 * Derived from Linux kernel MMU code.
 */
#include <asm/mmu.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/hcall.h>

#include "alloc_page.h"
#include "vmalloc.h"
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable.h>

#include <linux/compiler.h>

static pgd_t *identity_pgd;

bool vm_available(void) /* weak override */
{
	return cpu_has_radix;
}

bool mmu_enabled(void)
{
	return current_cpu()->pgtable != NULL;
}

void mmu_enable(pgd_t *pgtable)
{
	struct cpu *cpu = current_cpu();

	if (!pgtable)
		pgtable = identity_pgd;

	cpu->pgtable = pgtable;

	assert(!in_usermode());
	mtmsr(mfmsr() | (MSR_IR|MSR_DR));
}

void mmu_disable(void)
{
	struct cpu *cpu = current_cpu();

	cpu->pgtable = NULL;

	assert(!in_usermode());
	mtmsr(mfmsr() & ~(MSR_IR|MSR_DR));
}

static pteval_t *get_pte(pgd_t *pgtable, uintptr_t vaddr)
{
	pgd_t *pgd = pgd_offset(pgtable, vaddr);
	pud_t *pud = pud_alloc(pgd, vaddr);
	pmd_t *pmd = pmd_alloc(pud, vaddr);
	pte_t *pte = pte_alloc(pmd, vaddr);

	return &pte_val(*pte);
}

static pteval_t *install_pte(pgd_t *pgtable, uintptr_t vaddr, pteval_t pte)
{
	pteval_t *p_pte = get_pte(pgtable, vaddr);

	if (READ_ONCE(*p_pte) & cpu_to_be64(_PAGE_VALID)) {
		WRITE_ONCE(*p_pte, 0);
		flush_tlb_page(vaddr);
	}

	WRITE_ONCE(*p_pte, cpu_to_be64(pte));

	return p_pte;
}

static pteval_t *install_page_prot(pgd_t *pgtable, phys_addr_t phys,
				   uintptr_t vaddr, pgprot_t prot)
{
	pteval_t pte = phys;
	pte |= _PAGE_VALID | _PAGE_PTE;
	pte |= pgprot_val(prot);
	return install_pte(pgtable, vaddr, pte);
}

pteval_t *install_page(pgd_t *pgtable, phys_addr_t phys, void *virt)
{
	if (!pgtable)
		pgtable = identity_pgd;

	return install_page_prot(pgtable, phys, (uintptr_t)virt,
				 __pgprot(_PAGE_VALID | _PAGE_PTE |
					  _PAGE_READ | _PAGE_WRITE |
					  _PAGE_EXEC | _PAGE_ACCESSED |
					  _PAGE_DIRTY));
}

static pteval_t *follow_pte(pgd_t *pgtable, uintptr_t vaddr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(pgtable, vaddr);
	if (!pgd_valid(*pgd))
		return NULL;

	pud = pud_offset(pgd, vaddr);
	if (!pud_valid(*pud))
		return NULL;

	pmd = pmd_offset(pud, vaddr);
	if (!pmd_valid(*pmd))
		return NULL;
	if (pmd_huge(*pmd))
		return &pmd_val(*pmd);

	pte = pte_offset(pmd, vaddr);
	if (!pte_valid(*pte))
		return NULL;

	return &pte_val(*pte);
}

phys_addr_t virt_to_pte_phys(pgd_t *pgtable, void *virt)
{
	phys_addr_t mask;
	pteval_t *pteval;

	if (!pgtable)
		pgtable = identity_pgd;

	pteval = follow_pte(pgtable, (uintptr_t)virt);
	if (!pteval) {
		install_page(pgtable, (phys_addr_t)(unsigned long)virt, virt);
		return (phys_addr_t)(unsigned long)virt;
	}

	if (pmd_huge(__pmd(*pteval)))
		mask = PMD_MASK;
	else
		mask = PAGE_MASK;

	return (be64_to_cpu(*pteval) & PHYS_MASK & mask) |
		((phys_addr_t)(unsigned long)virt & ~mask);
}

struct partition_table_entry {
	uint64_t dw0;
	uint64_t dw1;
};

static struct partition_table_entry *partition_table;

struct process_table_entry {
	uint64_t dw0;
	uint64_t dw1;
};

static struct process_table_entry *process_table;

void *setup_mmu(phys_addr_t phys_end, void *unused)
{
	phys_addr_t addr;
	uint64_t dw0, dw1;

	if (identity_pgd)
		goto enable;

	assert_msg(cpu_has_radix, "MMU support requires radix MMU.");

	/* 32G address is reserved for vmalloc, cap phys_end at 31G */
	if (phys_end > (31ul << 30)) {
		/* print warning */
		phys_end = 31ul << 30;
	}

	init_alloc_vpage((void *)(32ul << 30));

	process_table = memalign_pages(SZ_4K, SZ_4K);
	memset(process_table, 0, SZ_4K);

	identity_pgd = pgd_alloc_one();

	dw0 = (unsigned long)identity_pgd;
	dw0 |= 16UL - 3; /* 64K pgd size */
	dw0 |= (0x2UL << 61) | (0x5UL << 5); /* 52-bit virt */
	process_table[1].dw0 = cpu_to_be64(dw0);

	if (machine_is_pseries()) {
		int ret;

		ret = hcall(H_REGISTER_PROCESS_TABLE, PTBL_NEW | PTBL_RADIX | PTBL_GTSE, process_table, 0, 0 /* 4K size */);
		assert_msg(!ret, "H_REGISTER_PROCESS_TABLE failed! err=%d\n", ret);
	} else if (machine_is_powernv()) {
		partition_table = memalign_pages(SZ_4K, SZ_4K);
		memset(partition_table, 0, SZ_4K);

		/* Reuse dw0 for partition table */
		dw0 |= 1ULL << 63; /* Host radix */
		dw1 = (unsigned long)process_table; /* 4K size */
		partition_table[0].dw0 = cpu_to_be64(dw0);
		partition_table[0].dw1 = cpu_to_be64(dw1);

	} else {
		/* Only pseries and powernv support radix so far */
		assert(0);
	}

	/*
	 * Avoid mapping page 0 so NULL dereferences fault. Test images
	 * run relocated well above 0, so nothing useful here except
	 * real-mode interrupt entry code.
	 */
	for (addr = PAGE_SIZE; addr < phys_end; addr += PAGE_SIZE)
		install_page(identity_pgd, addr, __va(addr));

enable:
	if (machine_is_powernv()) {
		mtspr(SPR_PTCR, (unsigned long)partition_table); /* 4KB size */

		mtspr(SPR_LPIDR, 0);
		/* Set LPCR[UPRT] and LPCR[HR] for radix */
		mtspr(SPR_LPCR, mfspr(SPR_LPCR) | (1ULL << 22) | (1ULL << 20));
	}

	/* PID=1 is used because PID=0 is also mapped in quadrant 3 */
	mtspr(SPR_PIDR, 1);

	mmu_enable(identity_pgd);

	return identity_pgd;
}

phys_addr_t __virt_to_phys(unsigned long addr)
{
	if (mmu_enabled()) {
		pgd_t *pgtable = current_cpu()->pgtable;
		return virt_to_pte_phys(pgtable, (void *)addr);
	}
	return addr;
}

unsigned long __phys_to_virt(phys_addr_t addr)
{
	/*
	 * We don't guarantee that phys_to_virt(virt_to_phys(vaddr)) == vaddr, but
	 * the default page tables do identity map all physical addresses, which
	 * means phys_to_virt(virt_to_phys((void *)paddr)) == paddr.
	 */
	assert(!mmu_enabled() || __virt_to_phys(addr) == addr);
	return addr;
}
