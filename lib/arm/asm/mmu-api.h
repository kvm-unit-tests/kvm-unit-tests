#ifndef __ASMARM_MMU_API_H_
#define __ASMARM_MMU_API_H_
extern pgd_t *mmu_idmap;
extern bool mmu_enabled(void);
extern void mmu_set_enabled(void);
extern void mmu_enable(pgd_t *pgtable);
extern void mmu_disable(void);
extern void mmu_enable_idmap(void);
extern void mmu_init_io_sect(pgd_t *pgtable, unsigned long virt_offset);
extern void mmu_set_range_sect(pgd_t *pgtable, unsigned long virt_offset,
			       unsigned long phys_start, unsigned long phys_end,
			       pgprot_t prot);
extern void mmu_set_range_ptes(pgd_t *pgtable, unsigned long virt_offset,
			       unsigned long phys_start, unsigned long phys_end,
			       pgprot_t prot);
#endif
