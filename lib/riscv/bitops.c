// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <bitops.h>

void set_bit(int nr, volatile unsigned long *addr)
{
	volatile unsigned long *word = addr + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);

	__sync_or_and_fetch(word, mask);
}

void clear_bit(int nr, volatile unsigned long *addr)
{
	volatile unsigned long *word = addr + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);

	__sync_and_and_fetch(word, ~mask);
}

int test_bit(int nr, const volatile unsigned long *addr)
{
	const volatile unsigned long *word = addr + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);

	return (*word & mask) != 0;
}

int test_and_set_bit(int nr, volatile unsigned long *addr)
{
	volatile unsigned long *word = addr + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);
	unsigned long old = __sync_fetch_and_or(word, mask);

	return (old & mask) != 0;
}

int test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	volatile unsigned long *word = addr + BIT_WORD(nr);
	unsigned long mask = BIT_MASK(nr);
	unsigned long old = __sync_fetch_and_and(word, ~mask);

	return (old & mask) != 0;
}
