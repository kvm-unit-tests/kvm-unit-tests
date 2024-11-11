/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_PROCESSOR_H_
#define _ASMRISCV_PROCESSOR_H_
#include <asm/csr.h>
#include <asm/ptrace.h>

#define EXCEPTION_CAUSE_MAX	24
#define INTERRUPT_CAUSE_MAX	16

typedef void (*exception_fn)(struct pt_regs *);

struct thread_info {
	int cpu;
	unsigned long hartid;
	unsigned long isa[1];
	unsigned long sp;
	exception_fn exception_handlers[EXCEPTION_CAUSE_MAX];
	exception_fn interrupt_handlers[INTERRUPT_CAUSE_MAX];
};

static inline struct thread_info *current_thread_info(void)
{
	return (struct thread_info *)csr_read(CSR_SSCRATCH);
}

static inline void local_irq_enable(void)
{
	csr_set(CSR_SSTATUS, SR_SIE);
}

static inline void local_irq_disable(void)
{
	csr_clear(CSR_SSTATUS, SR_SIE);
}

static inline void local_ipi_enable(void)
{
	csr_set(CSR_SIE, IE_SSIE);
}

static inline void local_ipi_disable(void)
{
	csr_clear(CSR_SIE, IE_SSIE);
}

static inline void ipi_ack(void)
{
	csr_clear(CSR_SIP, IE_SSIE);
}

void install_exception_handler(unsigned long cause, void (*handler)(struct pt_regs *));
void install_irq_handler(unsigned long cause, void (*handler)(struct pt_regs *));
void do_handle_exception(struct pt_regs *regs);
void thread_info_init(void);
void local_hart_init(void);

void show_regs(struct pt_regs *regs);

#endif /* _ASMRISCV_PROCESSOR_H_ */
