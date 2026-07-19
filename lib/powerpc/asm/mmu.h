/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMPOWERPC_MMU_H_
#define _ASMPOWERPC_MMU_H_

#include <asm/pgtable.h>

bool mmu_enabled(void);
void mmu_enable(pgd_t *pgtable);
void mmu_disable(void);

static inline void tlbie(unsigned long rb, unsigned long rs, int ric, int prs, int r)
{
	/* MMU is radix (>= POWER9), so can use P9 tlbie directly */
	asm volatile(
"	.machine push			\n"
"	.machine power9			\n"
"	ptesync				\n"
"	tlbie %0,%1,%2,%3,%4		\n"
"	eieio				\n"
"	tlbsync				\n"
"	ptesync				\n"
"	.machine pop			"
	:: "r"(rb), "r"(rs), "i"(ric), "i"(prs), "i"(r) : "memory");
}

static inline void tlbiel(unsigned long rb, unsigned long rs, int ric, int prs, int r)
{
	asm volatile(
"	.machine push			\n"
"	.machine power9			\n"
"	ptesync				\n"
"	tlbiel %0,%1,%2,%3,%4		\n"
"	ptesync				\n"
"	.machine pop			"
	:: "r"(rb), "r"(rs), "i"(ric), "i"(prs), "i"(r) : "memory");
}

static inline void flush_tlb_page(uintptr_t vaddr)
{
	unsigned long rb;
	unsigned long rs = (1ULL << 32); /* pid */
	unsigned long ap;

	/* AP should come from dt (for pseries, at least) */
	if (PAGE_SIZE == SZ_4K)
		ap = 0;
	else if (PAGE_SIZE == SZ_64K)
		ap = 5;
	else if (PAGE_SIZE == SZ_2M)
		ap = 1;
	else if (PAGE_SIZE == SZ_1G)
		ap = 2;
	else
		assert(0);

	rb = vaddr & ~((1UL << 12) - 1);
	rb |= ap << 5;

	tlbie(rb, rs, 0, 1, 1);
}

static inline void flush_tlb_page_local(uintptr_t vaddr)
{
	unsigned long rb;
	unsigned long rs = (1ULL << 32); /* pid */
	unsigned long ap;

	/* AP should come from dt (for pseries, at least) */
	if (PAGE_SIZE == SZ_4K)
		ap = 0;
	else if (PAGE_SIZE == SZ_64K)
		ap = 5;
	else if (PAGE_SIZE == SZ_2M)
		ap = 1;
	else if (PAGE_SIZE == SZ_1G)
		ap = 2;
	else
		assert(0);

	rb = vaddr & ~((1UL << 12) - 1);
	rb |= ap << 5;

	tlbiel(rb, rs, 0, 1, 1);
}

#endif
