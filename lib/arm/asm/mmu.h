#ifndef _ASMARM_MMU_H_
#define _ASMARM_MMU_H_
/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/barrier.h>

#define PTE_USER		L_PTE_USER
#define PTE_UXN			L_PTE_XN
#define PTE_PXN			L_PTE_PXN
#define PTE_RDONLY		PTE_AP2
#define PTE_SHARED		L_PTE_SHARED
#define PTE_AF			PTE_EXT_AF
#define PTE_WBWA		L_PTE_MT_WRITEALLOC
#define PTE_UNCACHED		L_PTE_MT_UNCACHED

/* See B3.18.7 TLB maintenance operations */

static inline void local_flush_tlb_all(void)
{
	dsb(nshst);
	/* TLBIALL */
	asm volatile("mcr p15, 0, %0, c8, c7, 0" :: "r" (0));
	dsb(nsh);
	isb();
}

static inline void flush_tlb_all(void)
{
	dsb(ishst);
	/* TLBIALLIS */
	asm volatile("mcr p15, 0, %0, c8, c3, 0" :: "r" (0));
	dsb(ish);
	isb();
}

static inline void flush_tlb_page(unsigned long vaddr)
{
	dsb(ishst);
	/* TLBIMVAAIS */
	asm volatile("mcr p15, 0, %0, c8, c3, 3" :: "r" (vaddr));
	dsb(ish);
	isb();
}

static inline void flush_dcache_addr(unsigned long vaddr)
{
	/* DCCIMVAC */
	asm volatile("mcr p15, 0, %0, c7, c14, 1" :: "r" (vaddr));
}

#include <asm/mmu-api.h>

#endif /* _ASMARM_MMU_H_ */
