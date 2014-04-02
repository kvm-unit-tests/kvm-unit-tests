#ifndef VM_H
#define VM_H

#include "processor.h"

#define PAGE_SIZE 4096ul
#ifdef __x86_64__
#define LARGE_PAGE_SIZE (512 * PAGE_SIZE)
#else
#define LARGE_PAGE_SIZE (1024 * PAGE_SIZE)
#endif

#define PTE_PRESENT (1ull << 0)
#define PTE_PSE     (1ull << 7)
#define PTE_WRITE   (1ull << 1)
#define PTE_USER    (1ull << 2)
#define PTE_ADDR    (0xffffffffff000ull)

#define X86_CR0_PE      0x00000001
#define X86_CR0_MP      0x00000002
#define X86_CR0_TS      0x00000008
#define X86_CR0_WP      0x00010000
#define X86_CR0_PG      0x80000000
#define X86_CR4_VMXE   0x00000001
#define X86_CR4_TSD     0x00000004
#define X86_CR4_DE      0x00000008
#define X86_CR4_PSE     0x00000010
#define X86_CR4_PAE     0x00000020
#define X86_CR4_PCIDE  0x00020000

void setup_vm();

void *vmalloc(unsigned long size);
void vfree(void *mem);
void *vmap(unsigned long long phys, unsigned long size);
void *alloc_vpage(void);
void *alloc_vpages(ulong nr);
uint64_t virt_to_phys_cr3(void *mem);

void install_pte(unsigned long *cr3,
                        int pte_level,
                        void *virt,
                        unsigned long pte,
                        unsigned long *pt_page);

void *alloc_page();

void install_large_page(unsigned long *cr3,unsigned long phys,
                               void *virt);
void install_page(unsigned long *cr3, unsigned long phys, void *virt);

static inline unsigned long virt_to_phys(const void *virt)
{
    return (unsigned long)virt;
}

static inline void *phys_to_virt(unsigned long phys)
{
    return (void *)phys;
}

#endif
