#ifndef _ASM_GENERIC_PAGE_H_
#define _ASM_GENERIC_PAGE_H_
/*
 * asm-generic/page.h
 *  adapted from the Linux kernel's include/asm-generic/page.h
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#define PAGE_SHIFT		12
#ifndef __ASSEMBLY__
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#else
#define PAGE_SIZE		(1 << PAGE_SHIFT)
#endif
#define PAGE_MASK		(~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)	(((addr) + (PAGE_SIZE-1)) & PAGE_MASK)

#ifndef __ASSEMBLY__
#define __va(x)			((void *)((unsigned long) (x)))
#define __pa(x)			((unsigned long) (x))
#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)
#define pfn_to_virt(pfn)	__va((pfn) << PAGE_SHIFT)
#endif

#endif
