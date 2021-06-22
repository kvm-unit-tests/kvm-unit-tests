#ifndef _VMALLOC_H_
#define _VMALLOC_H_

#include <asm/page.h>

/* Allocate consecutive virtual pages (without backing) */
extern void *alloc_vpages(ulong nr);
/* Allocate consecutive and aligned virtual pages (without backing) */
extern void *alloc_vpages_aligned(ulong nr, unsigned int alignment_order);

/* Allocate one virtual page (without backing) */
extern void *alloc_vpage(void);
/* Set the top of the virtual address space */
extern void init_alloc_vpage(void *top);
/* Set up the virtual allocator; also sets up the page allocator if needed */
extern void setup_vm(void);
/* As above, plus passes an opaque value to setup_mmu(). */
extern void __setup_vm(void *opaque);

/* Set up paging */
extern void *setup_mmu(phys_addr_t top, void *opaque);
/* Walk the page table and resolve the virtual address to a physical address */
extern phys_addr_t virt_to_pte_phys(pgd_t *pgtable, void *virt);
/* Map the virtual address to the physical address for the given page tables */
extern pteval_t *install_page(pgd_t *pgtable, phys_addr_t phys, void *virt);

/* Map consecutive physical pages */
void *vmap(phys_addr_t phys, size_t size);

#endif
