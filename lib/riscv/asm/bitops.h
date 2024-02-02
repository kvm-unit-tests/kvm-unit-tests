/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_BITOPS_H_
#define _ASMRISCV_BITOPS_H_

#ifndef _BITOPS_H_
#error only <bitops.h> can be included directly
#endif

#ifdef CONFIG_64BIT
#define BITS_PER_LONG	64
#else
#define BITS_PER_LONG	32
#endif

void set_bit(int nr, volatile unsigned long *addr);
void clear_bit(int nr, volatile unsigned long *addr);
int test_bit(int nr, const volatile unsigned long *addr);
int test_and_set_bit(int nr, volatile unsigned long *addr);
int test_and_clear_bit(int nr, volatile unsigned long *addr);

#endif /* _ASMRISCV_BITOPS_H_ */
