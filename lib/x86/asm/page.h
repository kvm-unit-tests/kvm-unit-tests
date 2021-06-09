#ifndef _ASMX86_PAGE_H_
#define _ASMX86_PAGE_H_
/*
 * Copyright (C) 2016, Red Hat Inc, Alexander Gordeev <agordeev@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */


#include <linux/const.h>
#include <bitops.h>

typedef unsigned long pteval_t;
typedef unsigned long pgd_t;

#include <asm-generic/page.h>

#ifndef __ASSEMBLY__

#define PAGE_ALIGN(addr)        ALIGN(addr, PAGE_SIZE)

#ifdef __x86_64__
#define LARGE_PAGE_SIZE	(512 * PAGE_SIZE)
#else
#define LARGE_PAGE_SIZE	(1024 * PAGE_SIZE)
#endif

#define PT_PRESENT_MASK		(1ull << 0)
#define PT_WRITABLE_MASK	(1ull << 1)
#define PT_USER_MASK		(1ull << 2)
#define PT_ACCESSED_MASK	(1ull << 5)
#define PT_DIRTY_MASK		(1ull << 6)
#define PT_PAGE_SIZE_MASK	(1ull << 7)
#define PT64_NX_MASK		(1ull << 63)
#define PT_ADDR_MASK		GENMASK_ULL(51, 12)

#define PDPTE64_PAGE_SIZE_MASK	  (1ull << 7)
#define PDPTE64_RSVD_MASK	  GENMASK_ULL(51, cpuid_maxphyaddr())

#define PT_AD_MASK              (PT_ACCESSED_MASK | PT_DIRTY_MASK)

#define PAE_PDPTE_RSVD_MASK     (GENMASK_ULL(63, cpuid_maxphyaddr()) |	\
				 GENMASK_ULL(8, 5) | GENMASK_ULL(2, 1))


#ifdef __x86_64__
#define	PAGE_LEVEL	4
#define	PDPT_LEVEL	3
#define	PGDIR_WIDTH	9
#define	PGDIR_MASK	511
#else
#define	PAGE_LEVEL	2
#define	PGDIR_WIDTH	10
#define	PGDIR_MASK	1023
#endif

#define PGDIR_BITS(lvl)        (((lvl) - 1) * PGDIR_WIDTH + PAGE_SHIFT)
#define PGDIR_OFFSET(va, lvl)  (((va) >> PGDIR_BITS(lvl)) & PGDIR_MASK)

#endif /* !__ASSEMBLY__ */
#endif
