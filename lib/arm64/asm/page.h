#ifndef _ASMARM64_PAGE_H_
#define _ASMARM64_PAGE_H_
/*
 * Adapted from
 *   arch/arm64/include/asm/pgtable-types.h
 *   include/asm-generic/pgtable-nopmd.h
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include <config.h>
#include <linux/const.h>
#include <libcflat.h>

#define VA_BITS			48

#define PAGE_SIZE		CONFIG_PAGE_SIZE
#if PAGE_SIZE == SZ_64K
#define PAGE_SHIFT		16
#elif PAGE_SIZE == SZ_16K
#define PAGE_SHIFT		14
#elif PAGE_SIZE == SZ_4K
#define PAGE_SHIFT		12
#else
#error Unsupported PAGE_SIZE
#endif
#define PAGE_MASK		(~(PAGE_SIZE-1))

/*
 * Since a page table descriptor is 8 bytes we have (PAGE_SHIFT - 3) bits
 * of virtual address at each page table level. So, to get the number of
 * page table levels needed, we round up the division of the number of
 * address bits (VA_BITS - PAGE_SHIFT) by (PAGE_SHIFT - 3).
 */
#define PGTABLE_LEVELS \
	(((VA_BITS - PAGE_SHIFT) + ((PAGE_SHIFT - 3) - 1)) / (PAGE_SHIFT - 3))

#ifndef __ASSEMBLY__

#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

typedef u64 pteval_t;
typedef u64 pmdval_t;
typedef u64 pudval_t;
typedef u64 pgdval_t;
typedef struct { pteval_t pte; } pte_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pteval_t pgprot; } pgprot_t;

#define pte_val(x)		((x).pte)
#define pmd_val(x)		((x).pmd)
#define pud_val(x)		((x).pud)
#define pgd_val(x)		((x).pgd)
#define pgprot_val(x)		((x).pgprot)

#define __pte(x)		((pte_t) { (x) } )
#define __pmd(x)		((pmd_t) { (x) } )
#define __pud(x)		((pud_t) { (x) } )
#define __pgd(x)		((pgd_t) { (x) } )
#define __pgprot(x)		((pgprot_t) { (x) } )

#define __va(x)			((void *)__phys_to_virt((phys_addr_t)(x)))
#define __pa(x)			__virt_to_phys((unsigned long)(x))

#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)
#define pfn_to_virt(pfn)	__va((pfn) << PAGE_SHIFT)

extern phys_addr_t __virt_to_phys(unsigned long addr);
extern unsigned long __phys_to_virt(phys_addr_t addr);

extern void *__ioremap(phys_addr_t phys_addr, size_t size);

#endif /* !__ASSEMBLY__ */
#endif /* _ASMARM64_PAGE_H_ */
