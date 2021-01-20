/* SPDX-License-Identifier: GPL-2.0 */
/*
 *    Bitops taken from the kernel as most developers are already used
 *    to them.
 *
 *    Copyright IBM Corp. 1999,2013
 *
 *    Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>,
 *
 */
#ifndef _ASMS390X_BITOPS_H_
#define _ASMS390X_BITOPS_H_

#ifndef _BITOPS_H_
#error only <bitops.h> can be included directly
#endif

#define BITS_PER_LONG	64

static inline bool test_bit(unsigned long nr,
			    const volatile unsigned long *ptr)
{
	const volatile unsigned char *addr;

	addr = ((const volatile unsigned char *)ptr);
	addr += (nr ^ (BITS_PER_LONG - 8)) >> 3;
	return (*addr >> (nr & 7)) & 1;
}

static inline bool test_bit_inv(unsigned long nr,
				const volatile unsigned long *ptr)
{
	return test_bit(nr ^ (BITS_PER_LONG - 1), ptr);
}

#endif
