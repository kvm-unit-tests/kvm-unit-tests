// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024, James Raphael Tiovalen <jamestiotio@gmail.com>
 */
#include <libcflat.h>
#include <asm/barrier.h>
#include <asm/delay.h>
#include <asm/timer.h>

void delay(uint64_t cycles)
{
	uint64_t start = timer_get_cycles();

	while ((timer_get_cycles() - start) < cycles)
		cpu_relax();
}

void udelay(unsigned long usecs)
{
	delay(usec_to_cycles((uint64_t)usecs));
}
