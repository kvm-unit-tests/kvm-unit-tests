#ifndef _ASMARM_PAGE_H_
#define _ASMARM_PAGE_H_
/*
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
#include <asm/setup.h>

#ifndef __virt_to_phys
#define __phys_to_virt(x)	((unsigned long) (x))
#define __virt_to_phys(x)	(x)
#endif

#define __va(x)			((void *)__phys_to_virt((phys_addr_t)(x)))
#define __pa(x)			__virt_to_phys((unsigned long)(x))

#define virt_to_pfn(kaddr)      (__pa(kaddr) >> PAGE_SHIFT)
#define pfn_to_virt(pfn)        __va((pfn) << PAGE_SHIFT)
#endif

#endif
