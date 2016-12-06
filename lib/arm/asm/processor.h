#ifndef _ASMARM_PROCESSOR_H_
#define _ASMARM_PROCESSOR_H_
/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/ptrace.h>
#include <asm/sysreg.h>

enum vector {
	EXCPTN_RST,
	EXCPTN_UND,
	EXCPTN_SVC,
	EXCPTN_PABT,
	EXCPTN_DABT,
	EXCPTN_ADDREXCPTN,
	EXCPTN_IRQ,
	EXCPTN_FIQ,
	EXCPTN_MAX,
};

typedef void (*exception_fn)(struct pt_regs *);
extern void install_exception_handler(enum vector v, exception_fn fn);

extern void show_regs(struct pt_regs *regs);

static inline unsigned long current_cpsr(void)
{
	unsigned long cpsr;
	asm volatile("mrs %0, cpsr" : "=r" (cpsr));
	return cpsr;
}

#define current_mode() (current_cpsr() & MODE_MASK)

#define MPIDR __ACCESS_CP15(c0, 0, c0, 5)
static inline unsigned int get_mpidr(void)
{
	return read_sysreg(MPIDR);
}

/* Only support Aff0 for now, up to 4 cpus */
#define mpidr_to_cpu(mpidr) ((int)((mpidr) & 0xff))

extern void start_usr(void (*func)(void *arg), void *arg, unsigned long sp_usr);
extern bool is_user(void);

#endif /* _ASMARM_PROCESSOR_H_ */
