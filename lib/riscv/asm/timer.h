/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_TIMER_H_
#define _ASMRISCV_TIMER_H_

#include <asm/csr.h>

extern void timer_get_frequency(void);
extern void timer_start(unsigned long duration_us);
extern void timer_stop(void);

static inline uint64_t timer_get_cycles(void)
{
	return csr_read(CSR_TIME);
}

static inline void timer_irq_enable(void)
{
	csr_set(CSR_SIE, IE_TIE);
}

static inline void timer_irq_disable(void)
{
	csr_clear(CSR_SIE, IE_TIE);
}

#endif /* _ASMRISCV_TIMER_H_ */
