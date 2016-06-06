#ifndef _ASM_X86_PAGE_H_
#define _ASM_X86_PAGE_H_
/*
 * Copyright (C) 2016, Red Hat Inc, Alexander Gordeev <agordeev@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */


#define PAGE_SIZE	4096ul
#ifdef __x86_64__
#define LARGE_PAGE_SIZE	(512 * PAGE_SIZE)
#else
#define LARGE_PAGE_SIZE	(1024 * PAGE_SIZE)
#endif

#define PTE_PRESENT	(1ull << 0)
#define PTE_WRITE	(1ull << 1)
#define PTE_USER	(1ull << 2)
#define PTE_PSE		(1ull << 7)
#define PTE_ADDR	(0xffffffffff000ull)

#ifdef __x86_64__
#define	PAGE_LEVEL	4
#define	PGDIR_WIDTH	9
#define	PGDIR_MASK	511
#else
#define	PAGE_LEVEL	2
#define	PGDIR_WIDTH	10
#define	PGDIR_MASK	1023
#endif

#endif
