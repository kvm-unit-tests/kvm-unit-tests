/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_DELAY_H_
#define _ASMRISCV_DELAY_H_

#include <libcflat.h>
#include <asm/setup.h>

extern void delay(uint64_t cycles);
extern void udelay(unsigned long usecs);

static inline uint64_t usec_to_cycles(uint64_t usec)
{
	return (timebase_frequency * usec) / 1000000;
}

#endif /* _ASMRISCV_DELAY_H_ */
