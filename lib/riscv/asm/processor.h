/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_PROCESSOR_H_
#define _ASMRISCV_PROCESSOR_H_
#include <asm/csr.h>
#include <asm/ptrace.h>

#define EXCEPTION_CAUSE_MAX	16

typedef void (*exception_fn)(struct pt_regs *);

struct thread_info {
	int cpu;
	unsigned long hartid;
	exception_fn exception_handlers[EXCEPTION_CAUSE_MAX];
};

static inline struct thread_info *current_thread_info(void)
{
	return (struct thread_info *)csr_read(CSR_SSCRATCH);
}

void install_exception_handler(unsigned long cause, void (*handler)(struct pt_regs *));
void do_handle_exception(struct pt_regs *regs);
void thread_info_init(void);

void show_regs(struct pt_regs *regs);

#endif /* _ASMRISCV_PROCESSOR_H_ */
