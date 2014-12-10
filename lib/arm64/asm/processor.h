#ifndef _ASMARM64_PROCESSOR_H_
#define _ASMARM64_PROCESSOR_H_
/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/ptrace.h>

enum vector {
	EL1T_SYNC,
	EL1T_IRQ,
	EL1T_FIQ,
	EL1T_ERROR,
	EL1H_SYNC,
	EL1H_IRQ,
	EL1H_FIQ,
	EL1H_ERROR,
	EL0_SYNC_64,
	EL0_IRQ_64,
	EL0_FIQ_64,
	EL0_ERROR_64,
	EL0_SYNC_32,
	EL0_IRQ_32,
	EL0_FIQ_32,
	EL0_ERROR_32,
	VECTOR_MAX,
};

#define EC_MAX 64

typedef void (*vector_fn)(enum vector v, struct pt_regs *regs,
			  unsigned int esr);
typedef void (*exception_fn)(struct pt_regs *regs, unsigned int esr);
extern void install_vector_handler(enum vector v, vector_fn fn);
extern void install_exception_handler(enum vector v, unsigned int ec,
				      exception_fn fn);

extern void show_regs(struct pt_regs *regs);
extern void *get_sp(void);

static inline unsigned long current_level(void)
{
	unsigned long el;
	asm volatile("mrs %0, CurrentEL" : "=r" (el));
	return el & 0xc;
}

extern bool user_mode;
extern void start_usr(void (*func)(void *arg), void *arg, unsigned long sp_usr);

#endif /* _ASMARM64_PROCESSOR_H_ */
