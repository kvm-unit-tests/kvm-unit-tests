// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <limits.h>
#include <asm/csr.h>
#include <asm/isa.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/smp.h>

extern unsigned long ImageBase;

void show_regs(struct pt_regs *regs)
{
	struct thread_info *info = current_thread_info();
	uintptr_t loadaddr = (uintptr_t)&ImageBase;
	unsigned int w = __riscv_xlen / 4;

	printf("Load address: %" PRIxPTR "\n", loadaddr);
	printf("CPU%3d : hartid=%lx\n", info->cpu, info->hartid);
	printf("status : %.*lx\n", w, regs->status);
	printf("cause  : %.*lx\n", w, regs->cause);
	printf("badaddr: %.*lx\n", w, regs->badaddr);
	printf("pc: %.*lx (%lx) ra: %.*lx (%lx)\n", w, regs->epc, regs->epc - loadaddr, w, regs->ra, regs->ra - loadaddr);
	printf("sp: %.*lx gp: %.*lx tp : %.*lx\n", w, regs->sp, w, regs->gp, w, regs->tp);
	printf("a0: %.*lx a1: %.*lx a2 : %.*lx a3 : %.*lx\n", w, regs->a0, w, regs->a1, w, regs->a2, w, regs->a3);
	printf("a4: %.*lx a5: %.*lx a6 : %.*lx a7 : %.*lx\n", w, regs->a4, w, regs->a5, w, regs->a6, w, regs->a7);
	printf("t0: %.*lx t1: %.*lx t2 : %.*lx t3 : %.*lx\n", w, regs->t0, w, regs->t1, w, regs->t2, w, regs->t3);
	printf("t4: %.*lx t5: %.*lx t6 : %.*lx\n", w, regs->t4, w, regs->t5, w, regs->t6);
	printf("s0: %.*lx s1: %.*lx s2 : %.*lx s3 : %.*lx\n", w, regs->s0, w, regs->s1, w, regs->s2, w, regs->s3);
	printf("s4: %.*lx s5: %.*lx s6 : %.*lx s7 : %.*lx\n", w, regs->s4, w, regs->s5, w, regs->s6, w, regs->s7);
	printf("s8: %.*lx s9: %.*lx s10: %.*lx s11: %.*lx\n", w, regs->s8, w, regs->s9, w, regs->s10, w, regs->s11);
}

void do_handle_exception(struct pt_regs *regs)
{
	struct thread_info *info = current_thread_info();

	if (regs->cause & CAUSE_IRQ_FLAG) {
		unsigned long irq_cause = regs->cause & ~CAUSE_IRQ_FLAG;

		assert(irq_cause < INTERRUPT_CAUSE_MAX);
		if (info->interrupt_handlers[irq_cause]) {
			info->interrupt_handlers[irq_cause](regs);
			return;
		}
	} else {
		assert(regs->cause < EXCEPTION_CAUSE_MAX);

		if (info->exception_handlers[regs->cause]) {
			info->exception_handlers[regs->cause](regs);
			return;
		}
	}

	show_regs(regs);
	dump_frame_stack((void *)regs->epc, (void *)regs->s0);
	abort();
}

void install_irq_handler(unsigned long cause, void (*handler)(struct pt_regs *))
{
	struct thread_info *info = current_thread_info();

	assert(cause < INTERRUPT_CAUSE_MAX);
	info->interrupt_handlers[cause] = handler;
}

void install_exception_handler(unsigned long cause, void (*handler)(struct pt_regs *))
{
	struct thread_info *info = current_thread_info();

	assert(cause < EXCEPTION_CAUSE_MAX);
	info->exception_handlers[cause] = handler;
}

void thread_info_init(void)
{
	unsigned long hartid = csr_read(CSR_SSCRATCH);
	int cpu = hartid_to_cpu(hartid);

	isa_init(&cpus[cpu]);
	csr_write(CSR_SSCRATCH, &cpus[cpu]);
}

void local_hart_init(void)
{
	if (cpu_has_extension(smp_processor_id(), ISA_SSTC)) {
		csr_write(CSR_STIMECMP, ULONG_MAX);
		if (__riscv_xlen == 32)
			csr_write(CSR_STIMECMPH, ULONG_MAX);
	}
}
