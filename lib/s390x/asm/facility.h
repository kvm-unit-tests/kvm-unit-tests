/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 */
#ifndef _ASMS390X_FACILITY_H_
#define _ASMS390X_FACILITY_H_

#include <libcflat.h>
#include <asm/facility.h>
#include <asm/arch_def.h>
#include <bitops.h>

#define NB_STFL_DOUBLEWORDS 32
extern uint64_t stfl_doublewords[];

static inline bool test_facility(int nr)
{
	return test_bit_inv(nr, stfl_doublewords);
}

static inline void stfl(void)
{
	asm volatile("	stfl	0(0)\n" : : : "memory");
}

static inline void stfle(uint64_t *fac, unsigned int nb_doublewords)
{
	register unsigned long r0 asm("0") = nb_doublewords - 1;

	asm volatile("	.insn	s,0xb2b00000,0(%1)\n"
		     : "+d" (r0) : "a" (fac) : "memory", "cc");
}

static inline void setup_facilities(void)
{
	struct lowcore *lc = NULL;

	stfl();
	memcpy(stfl_doublewords, &lc->stfl, sizeof(lc->stfl));
	if (test_facility(7))
		stfle(stfl_doublewords, NB_STFL_DOUBLEWORDS);
}

#endif
