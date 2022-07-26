#ifndef _X86_VM_H_
#define _X86_VM_H_

#include "processor.h"
#include "asm/page.h"
#include "asm/io.h"
#include "asm/bitops.h"

void setup_5level_page_table(void);

struct pte_search {
	int level;
	pteval_t *pte;
};

static inline bool found_huge_pte(struct pte_search search)
{
	return (search.level == 2 || search.level == 3) &&
	       (*search.pte & PT_PRESENT_MASK) &&
	       (*search.pte & PT_PAGE_SIZE_MASK);
}

static inline bool found_leaf_pte(struct pte_search search)
{
	return search.level == 1 || found_huge_pte(search);
}

struct pte_search find_pte_level(pgd_t *cr3, void *virt,
				 int lowest_level);
pteval_t *get_pte(pgd_t *cr3, void *virt);
pteval_t *get_pte_level(pgd_t *cr3, void *virt, int pte_level);
pteval_t *install_pte(pgd_t *cr3,
		      int pte_level,
		      void *virt,
		      pteval_t pte,
		      pteval_t *pt_page);

pteval_t *install_large_page(pgd_t *cr3, phys_addr_t phys, void *virt);
void install_pages(pgd_t *cr3, phys_addr_t phys, size_t len, void *virt);
bool any_present_pages(pgd_t *cr3, void *virt, size_t len);
void set_pte_opt_mask(void);
void reset_pte_opt_mask(void);

enum x86_mmu_flags {
	X86_MMU_MAP_USER	= BIT(0),
	X86_MMU_MAP_HUGE	= BIT(1),
};
void __setup_mmu_range(pgd_t *cr3, phys_addr_t start, size_t len,
		       enum x86_mmu_flags mmu_flags);

static inline void *current_page_table(void)
{
	return phys_to_virt(read_cr3());
}

void split_large_page(unsigned long *ptep, int level);
void force_4k_page(void *addr);

struct vm_vcpu_info {
        u64 cr3;
        u64 cr4;
        u64 cr0;
};

typedef void (*pte_callback_t)(struct pte_search search, void *va);
void walk_pte(void *virt, size_t len, pte_callback_t callback);

#endif
