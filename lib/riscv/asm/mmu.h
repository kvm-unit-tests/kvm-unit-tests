/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_MMU_H_
#define _ASMRISCV_MMU_H_
#include <libcflat.h>
#include <asm/csr.h>
#include <asm/page.h>
#include <asm/pgtable.h>

static inline pgd_t *current_pgtable(void)
{
	return (pgd_t *)((csr_read(CSR_SATP) & SATP_PPN) << PAGE_SHIFT);
}

void mmu_set_range_ptes(pgd_t *pgtable, uintptr_t virt_offset,
			phys_addr_t phys_start, phys_addr_t phys_end,
			pgprot_t prot, bool flush);
void __mmu_enable(unsigned long satp);
void mmu_enable(unsigned long mode, pgd_t *pgtable);
void mmu_disable(void);

void setup_mmu(void);

static inline void local_flush_tlb_page(unsigned long addr)
{
	asm volatile("sfence.vma %0" : : "r" (addr) : "memory");
}

/*
 * Get the pte pointer for a virtual address, even if it's not mapped.
 * Constructs upper levels of the table as necessary.
 */
pte_t *get_pte(pgd_t *pgtable, uintptr_t vaddr);

#endif /* _ASMRISCV_MMU_H_ */
