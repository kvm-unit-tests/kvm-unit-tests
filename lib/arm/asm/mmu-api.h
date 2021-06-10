#ifndef _ASMARM_MMU_API_H_
#define _ASMARM_MMU_API_H_

#include <asm/page.h>
#include <stdbool.h>

extern pgd_t *mmu_idmap;
extern bool mmu_enabled(void);
extern void mmu_mark_enabled(int cpu);
extern void mmu_mark_disabled(int cpu);
extern void mmu_enable(pgd_t *pgtable);
extern void mmu_disable(void);

extern void mmu_set_range_sect(pgd_t *pgtable, uintptr_t virt_offset,
			       phys_addr_t phys_start, phys_addr_t phys_end,
			       pgprot_t prot);
extern void mmu_set_range_ptes(pgd_t *pgtable, uintptr_t virt_offset,
			       phys_addr_t phys_start, phys_addr_t phys_end,
			       pgprot_t prot);
extern pteval_t *mmu_get_pte(pgd_t *pgtable, uintptr_t vaddr);
extern void mmu_clear_user(pgd_t *pgtable, unsigned long vaddr);
#endif
