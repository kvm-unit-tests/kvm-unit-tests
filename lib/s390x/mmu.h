/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x mmu functions
 *
 * Copyright (c) 2018 IBM Corp
 *
 * Authors:
 *	Janosch Frank <frankja@linux.ibm.com>
 */
#ifndef _S390X_MMU_H_
#define _S390X_MMU_H_

enum pgt_level {
	pgtable_level_pgd = 1,
	pgtable_level_p4d,
	pgtable_level_pud,
	pgtable_level_pmd,
	pgtable_level_pte,
};

/*
 * Splits the pagetables down to the given DAT tables level.
 * Returns a pointer to the DAT table entry of the given level.
 * @pgtable root of the page table tree
 * @vaddr address whose page tables are to split
 * @level 3 (for 2GB pud), 4 (for 1 MB pmd) or 5 (for 4KB pages)
 */
void *split_page(pgd_t *pgtable, void *vaddr, enum pgt_level level);

/*
 * Applies the given protection bits to the given DAT tables level,
 * splitting if necessary.
 * @pgtable root of the page table tree
 * @vaddr address whose protection bits are to be changed
 * @prot the protection bits to set
 * @level 3 (for 2GB pud), 4 (for 1MB pmd) or 5 (for 4KB pages)
 */
void protect_dat_entry(void *vaddr, unsigned long prot, enum pgt_level level);

/*
 * Clears the given protection bits from the given DAT tables level,
 * splitting if necessary.
 * @pgtable root of the page table tree
 * @vaddr address whose protection bits are to be changed
 * @prot the protection bits to clear
 * @level 3 (for 2GB pud), 4 (for 1MB pmd) or 5 (for 4kB pages)
 */
void unprotect_dat_entry(void *vaddr, unsigned long prot, enum pgt_level level);

/*
 * Applies the given protection bits to the given 4kB pages range,
 * splitting if necessary.
 * @start starting address whose protection bits are to be changed
 * @len size in bytes
 * @prot the protection bits to set
 */
void protect_range(void *start, unsigned long len, unsigned long prot);

/*
 * Clears the given protection bits from the given 4kB pages range,
 * splitting if necessary.
 * @start starting address whose protection bits are to be changed
 * @len size in bytes
 * @prot the protection bits to set
 */
void unprotect_range(void *start, unsigned long len, unsigned long prot);

/* Similar to install_page, maps the virtual address to the physical address
 * for the given page tables, using 1MB large pages.
 * Returns a pointer to the DAT table entry.
 * @pgtable root of the page table tree
 * @phys physical address to map, must be 1MB aligned!
 * @vaddr virtual address to map, must be 1MB aligned!
 */
pmdval_t *install_large_page(pgd_t *pgtable, phys_addr_t phys, void *vaddr);

/* Similar to install_page, maps the virtual address to the physical address
 * for the given page tables, using 2GB huge pages.
 * Returns a pointer to the DAT table entry.
 * @pgtable root of the page table tree
 * @phys physical address to map, must be 2GB aligned!
 * @vaddr virtual address to map, must be 2GB aligned!
 */
pudval_t *install_huge_page(pgd_t *pgtable, phys_addr_t phys, void *vaddr);

static inline void protect_page(void *vaddr, unsigned long prot)
{
	protect_dat_entry(vaddr, prot, pgtable_level_pte);
}

static inline void unprotect_page(void *vaddr, unsigned long prot)
{
	unprotect_dat_entry(vaddr, prot, pgtable_level_pte);
}

void *get_dat_entry(pgd_t *pgtable, void *vaddr, unsigned int level);

#endif /* _ASMS390X_MMU_H_ */
