/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_TIMER_H_
#define _ASMRISCV_TIMER_H_

#include <asm/csr.h>

extern void timer_get_frequency(void);

static inline uint64_t timer_get_cycles(void)
{
	return csr_read(CSR_TIME);
}

#endif /* _ASMRISCV_TIMER_H_ */
