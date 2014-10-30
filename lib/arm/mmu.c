/*
 * MMU enable and page table manipulation functions
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "asm/setup.h"
#include "asm/mmu.h"
#include "asm/pgtable-hwdef.h"

static bool mmu_on;
static pgd_t idmap[PTRS_PER_PGD] __attribute__((aligned(L1_CACHE_BYTES)));

bool mmu_enabled(void)
{
	return mmu_on;
}

extern void asm_mmu_enable(phys_addr_t pgtable);
void mmu_enable(pgd_t *pgtable)
{
	asm_mmu_enable(__pa(pgtable));
	flush_tlb_all();
	mmu_on = true;
}

void mmu_init_io_sect(pgd_t *pgtable)
{
	/*
	 * mach-virt reserves the first 1G section for I/O
	 */
	pgd_val(pgtable[0]) = PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_USER;
	pgd_val(pgtable[0]) |= PMD_SECT_UNCACHED;
}

void mmu_enable_idmap(void)
{
	unsigned long sect, end;

	mmu_init_io_sect(idmap);

	end = sizeof(long) == 8 || !(PHYS_END >> 32) ? PHYS_END : 0xfffff000;

	for (sect = PHYS_OFFSET & PGDIR_MASK; sect < end; sect += PGDIR_SIZE) {
		int i = sect >> PGDIR_SHIFT;
		pgd_val(idmap[i]) = sect;
		pgd_val(idmap[i]) |= PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_USER;
		pgd_val(idmap[i]) |= PMD_SECT_S | PMD_SECT_WBWA;
	}

	mmu_enable(idmap);
}
