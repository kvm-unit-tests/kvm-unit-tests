#ifndef __ASMARM_MMU_H_
#define __ASMARM_MMU_H_
/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/setup.h>
#include <asm/barrier.h>
#include <alloc.h>

#define PTRS_PER_PGD	4
#define PGDIR_SHIFT	30
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~((1 << PGDIR_SHIFT) - 1))

#define pgd_free(pgd) free(pgd)
static inline pgd_t *pgd_alloc(void)
{
	pgd_t *pgd = memalign(L1_CACHE_BYTES, PTRS_PER_PGD * sizeof(pgd_t));
	memset(pgd, 0, PTRS_PER_PGD * sizeof(pgd_t));
	return pgd;
}

static inline void local_flush_tlb_all(void)
{
	asm volatile("mcr p15, 0, %0, c8, c7, 0" :: "r" (0));
	dsb();
	isb();
}

static inline void flush_tlb_all(void)
{
	//TODO
	local_flush_tlb_all();
}

extern bool mmu_enabled(void);
extern void mmu_enable(pgd_t *pgtable);
extern void mmu_enable_idmap(void);
extern void mmu_init_io_sect(pgd_t *pgtable);

#endif /* __ASMARM_MMU_H_ */
