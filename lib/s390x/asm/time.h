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

static inline uint64_t get_clock_ms(void)
{
	uint64_t clk;

	asm volatile(" stck %0 " : : "Q"(clk) : "memory");

	/* Bit 51 is incrememented each microsecond */
	return (clk >> (63 - 51)) / 1000;
}

#endif
