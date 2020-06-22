#ifndef VMALLOC_H
#define VMALLOC_H 1

#include <asm/page.h>

/* Allocate consecutive virtual pages (without backing) */
extern void *alloc_vpages(ulong nr);
/* Allocate one virtual page (without backing) */
extern void *alloc_vpage(void);
/* Set the top of the virtual address space */
extern void init_alloc_vpage(void *top);
/* Set up the virtual allocator; also sets up the page allocator if needed */
extern void setup_vm(void);

/* Set up paging */
extern void *setup_mmu(phys_addr_t top);
/* Walk the page table and resolve the virtual address to a physical address */
extern phys_addr_t virt_to_pte_phys(pgd_t *pgtable, void *virt);
/* Map the virtual address to the physical address for the given page tables */
extern pteval_t *install_page(pgd_t *pgtable, phys_addr_t phys, void *virt);

/* Map consecutive physical pages */
void *vmap(phys_addr_t phys, size_t size);

#endif
