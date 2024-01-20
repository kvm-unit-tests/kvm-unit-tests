// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc_page.h>
#include <memregions.h>
#include <asm/csr.h>
#include <asm/io.h>
#include <asm/mmu.h>
#include <asm/page.h>

static pgd_t *__initial_pgtable;

static int pte_index(uintptr_t vaddr, int level)
{
	return (vaddr >> (PGDIR_BITS * level + PAGE_SHIFT)) & PGDIR_MASK;
}

static pte_t *pteval_to_ptep(pteval_t pteval)
{
	return (pte_t *)(((pteval & PTE_PPN) >> PPN_SHIFT) << PAGE_SHIFT);
}

static pteval_t ptep_to_pteval(pte_t *ptep)
{
	return ((pteval_t)ptep >> PAGE_SHIFT) << PPN_SHIFT;
}

pte_t *get_pte(pgd_t *pgtable, uintptr_t vaddr)
{
	pte_t *ptep = (pte_t *)pgtable;

	assert(pgtable && !((uintptr_t)pgtable & ~PAGE_MASK));

	for (int level = NR_LEVELS - 1; level > 0; --level) {
		pte_t *next = &ptep[pte_index(vaddr, level)];
		if (!pte_val(*next)) {
			void *page = alloc_page();
			*next = __pte(ptep_to_pteval(page) | _PAGE_PRESENT);
		}
		ptep = pteval_to_ptep(pte_val(*next));
	}
	ptep = &ptep[pte_index(vaddr, 0)];

	return ptep;
}

static pteval_t *__install_page(pgd_t *pgtable, phys_addr_t paddr,
				uintptr_t vaddr, pgprot_t prot, bool flush)
{
	phys_addr_t ppn = (paddr >> PAGE_SHIFT) << PPN_SHIFT;
	pteval_t pte = (pteval_t)ppn;
	pte_t *ptep;

	assert(!(ppn & ~PTE_PPN));

	ptep = get_pte(pgtable, vaddr);
	*ptep = __pte(pte | pgprot_val(prot) | _PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY);

	if (flush)
		local_flush_tlb_page(vaddr);

	return (pteval_t *)ptep;
}

void mmu_set_range_ptes(pgd_t *pgtable, uintptr_t virt_offset,
			phys_addr_t phys_start, phys_addr_t phys_end,
			pgprot_t prot, bool flush)
{
	phys_addr_t paddr = phys_start & PAGE_MASK;
	uintptr_t vaddr = virt_offset & PAGE_MASK;
	uintptr_t virt_end = phys_end - paddr + vaddr;

	assert(phys_start < phys_end);

	for (; vaddr < virt_end; vaddr += PAGE_SIZE, paddr += PAGE_SIZE)
		__install_page(pgtable, paddr, vaddr, prot, flush);
}

void mmu_disable(void)
{
	__asm__ __volatile__ (
	"	csrw	" xstr(CSR_SATP) ", zero\n"
	"	sfence.vma\n"
	: : : "memory");
}

void __mmu_enable(unsigned long satp)
{
	__asm__ __volatile__ (
	"	sfence.vma\n"
	"	csrw	" xstr(CSR_SATP) ", %0\n"
	: : "r" (satp) : "memory");
}

void mmu_enable(unsigned long mode, pgd_t *pgtable)
{
	unsigned long ppn = (unsigned long)pgtable >> PAGE_SHIFT;
	unsigned long satp = mode | ppn;

	assert(!(ppn & ~SATP_PPN));
	__mmu_enable(satp);
}

void setup_mmu(void)
{
	struct mem_region *r;
	pgd_t *pgtable;

	if (!__initial_pgtable)
		__initial_pgtable = alloc_page();
	pgtable = __initial_pgtable;

	for (r = mem_regions; r->end; ++r) {
		if (r->flags & (MR_F_IO | MR_F_RESERVED))
			continue;
		if (r->flags & MR_F_CODE) {
			mmu_set_range_ptes(pgtable, r->start, r->start, r->end,
					   __pgprot(_PAGE_READ | _PAGE_EXEC), false);
		} else {
			mmu_set_range_ptes(pgtable, r->start, r->start, r->end,
					   __pgprot(_PAGE_READ | _PAGE_WRITE), false);
		}
	}

	mmu_enable(SATP_MODE_DEFAULT, pgtable);
}

void __iomem *ioremap(phys_addr_t phys_addr, size_t size)
{
	phys_addr_t start = phys_addr & PAGE_MASK;
	phys_addr_t end = PAGE_ALIGN(phys_addr + size);
	pgd_t *pgtable = current_pgtable();
	bool flush = true;

	assert(sizeof(long) == 8 || !(phys_addr >> 32));

	if (!pgtable) {
		if (!__initial_pgtable)
			__initial_pgtable = alloc_page();
		pgtable = __initial_pgtable;
		flush = false;
	}

	mmu_set_range_ptes(pgtable, start, start, end,
			   __pgprot(_PAGE_READ | _PAGE_WRITE), flush);

	return (void __iomem *)(unsigned long)phys_addr;
}
