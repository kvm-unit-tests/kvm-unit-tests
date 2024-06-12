/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMPPC64_PGTABLE_HWDEF_H_
#define _ASMPPC64_PGTABLE_HWDEF_H_
/*
 * Copyright (C) 2024, IBM Inc, Nicholas Piggin <npiggin@gmail.com>
 *
 * Derived from Linux kernel MMU code.
 */

#include <asm/page.h>

#define UL(x) _AC(x, UL)

/*
 * Book3S-64 Radix page table
 */
#define PGDIR_SHIFT		39
#define PUD_SHIFT		30
#define PMD_SHIFT		21

#define PTRS_PER_PGD		(SZ_64K / 8)
#define PTRS_PER_PUD		(SZ_4K / 8)
#define PTRS_PER_PMD		(SZ_4K / 8)
#if PAGE_SIZE == SZ_4K
#define PTRS_PER_PTE		(SZ_4K / 8)
#else /* 64K */
#define PTRS_PER_PTE		(256 / 8)
#endif

#define PGDIR_SIZE		(UL(1) << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))

#define PUD_SIZE		(UL(1) << PUD_SHIFT)
#define PUD_MASK		(~(PUD_SIZE-1))

#define PMD_SIZE		(UL(1) << PMD_SHIFT)
#define PMD_MASK		(~(PMD_SIZE-1))

#define _PAGE_VALID		0x8000000000000000UL
#define _PAGE_PTE		0x4000000000000000UL

#define _PAGE_EXEC		0x00001 /* execute permission */
#define _PAGE_WRITE		0x00002 /* write access allowed */
#define _PAGE_READ		0x00004 /* read access allowed */
#define _PAGE_PRIVILEGED	0x00008 /* kernel access only */
#define _PAGE_SAO		0x00010 /* Strong access order */
#define _PAGE_NON_IDEMPOTENT	0x00020 /* non idempotent memory */
#define _PAGE_TOLERANT		0x00030 /* tolerant memory, cache inhibited */
#define _PAGE_DIRTY		0x00080 /* C: page changed */
#define _PAGE_ACCESSED		0x00100 /* R: page referenced */

/*
 * Software bits
 */
#define _PAGE_SW0		0x2000000000000000UL
#define _PAGE_SW1		0x00800UL
#define _PAGE_SW2		0x00400UL
#define _PAGE_SW3		0x00200UL

/*
 * Highest possible physical address.
 */
#define PHYS_MASK_SHIFT		(48)
#define PHYS_MASK		((UL(1) << PHYS_MASK_SHIFT) - 1)

#endif /* _ASMPPC64_PGTABLE_HWDEF_H_ */
