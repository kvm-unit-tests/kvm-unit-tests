/*
 * Copyright (C) 2020, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#ifndef _ASMARM_TIMER_H_
#define _ASMARM_TIMER_H_

#define ARCH_TIMER_CTL_ENABLE  (1 << 0)
#define ARCH_TIMER_CTL_IMASK   (1 << 1)
#define ARCH_TIMER_CTL_ISTATUS (1 << 2)

#ifndef __ASSEMBLER__

struct timer_state {
	struct {
		u32 irq;
		u32 irq_flags;
	} ptimer;
	struct {
		u32 irq;
		u32 irq_flags;
	} vtimer;
	struct {
		u32 irq;
		u32 irq_flags;
	} hptimer;
	struct {
		u32 irq;
		u32 irq_flags;
	} hvtimer;
};
extern struct timer_state __timer_state;

#define TIMER_PTIMER_IRQ (__timer_state.ptimer.irq)
#define TIMER_VTIMER_IRQ (__timer_state.vtimer.irq)

#define TIMER_HPTIMER_IRQ (__timer_state.hptimer.irq)
#define TIMER_HVTIMER_IRQ (__timer_state.hvtimer.irq)

void timer_save_state(void);

#endif /* !__ASSEMBLER__ */
#endif /* _ASMARM_TIMER_H_ */
