/*
 * Clock utilities for s390
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *
 * Copied from the s390/intercept test by:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */
#ifndef ASM_S390X_TIME_H
#define ASM_S390X_TIME_H

#define STCK_SHIFT_US	(63 - 51)
#define STCK_MAX	((1UL << 52) - 1)

static inline uint64_t get_clock_us(void)
{
	uint64_t clk;

	asm volatile(" stck %0 " : : "Q"(clk) : "memory");

	return clk >> STCK_SHIFT_US;
}

static inline uint64_t get_clock_ms(void)
{
	return get_clock_us() / 1000;
}

static inline void udelay(unsigned long us)
{
	unsigned long startclk = get_clock_us();
	unsigned long c;

	do {
		c = get_clock_us();
		if (c < startclk)
			c += STCK_MAX;
	} while (c < startclk + us);
}

static inline void mdelay(unsigned long ms)
{
	udelay(ms * 1000);
}

#endif
