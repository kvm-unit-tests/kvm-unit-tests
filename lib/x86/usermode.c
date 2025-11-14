#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/apic-defs.h"
#include "x86/apic.h"
#include "x86/desc.h"
#include "x86/isr.h"
#include "alloc.h"
#include "setjmp.h"
#include "usermode.h"

#include "libcflat.h"
#include <stdint.h>

#define USERMODE_STACK_SIZE	0x2000
#define RET_TO_KERNEL_IRQ	0x20

static jmp_buf jmpbuf;

static void restore_exec_to_jmpbuf(void)
{
	longjmp(jmpbuf, 1);
}

static void restore_exec_to_jmpbuf_exception_handler(struct ex_regs *regs)
{
	this_cpu_write_exception_vector(regs->vector);
	this_cpu_write_exception_rflags_rf((regs->rflags >> 16) & 1);
	this_cpu_write_exception_error_code(regs->error_code);

	/* longjmp must happen after iret, so do not do it now.  */
	regs->rip = (unsigned long)&restore_exec_to_jmpbuf;
	regs->cs = KERNEL_CS;
#ifdef __x86_64__
	regs->ss = KERNEL_DS;
#endif
}

uint64_t run_in_user(usermode_func func, unsigned int fault_vector,
		uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4, bool *raised_vector)
{
	extern char ret_to_kernel;
	volatile uint64_t rax = 0;
	static unsigned char user_stack[USERMODE_STACK_SIZE];
	handler old_ex;

	*raised_vector = 0;
	set_idt_entry(RET_TO_KERNEL_IRQ, &ret_to_kernel, 3);
	old_ex = handle_exception(fault_vector,
				  restore_exec_to_jmpbuf_exception_handler);

	if (setjmp(jmpbuf) != 0) {
		handle_exception(fault_vector, old_ex);
		*raised_vector = 1;
		return 0;
	}

	asm volatile (
			/* Prepare kernel SP for exception handlers */
			"mov %%rsp, %[rsp0]\n\t"
			/* Load user_ds to DS and ES */
			"mov %[user_ds], %%ax\n\t"
			"mov %%ax, %%ds\n\t"
			"mov %%ax, %%es\n\t"
			/* IRET into user mode */
			"pushq %[user_ds]\n\t"
			"pushq %[user_stack_top]\n\t"
			"pushfq\n\t"
			"pushq %[user_cs]\n\t"
			"lea user_mode(%%rip), %%rax\n\t"
			"pushq %%rax\n\t"
			"iretq\n"

			"user_mode:\n\t"
			/* Back up volatile registers before invoking func */
			"push %%rcx\n\t"
			"push %%rdx\n\t"
			"push %%rdi\n\t"
			"push %%rsi\n\t"
			"push %%r8\n\t"
			"push %%r9\n\t"
			"push %%r10\n\t"
			"push %%r11\n\t"
			/* Call user mode function */
			"mov %[arg1], %%rdi\n\t"
			"mov %[arg2], %%rsi\n\t"
			"mov %[arg3], %%rdx\n\t"
			"mov %[arg4], %%rcx\n\t"
			"call *%[func]\n\t"
			/* Restore registers */
			"pop %%r11\n\t"
			"pop %%r10\n\t"
			"pop %%r9\n\t"
			"pop %%r8\n\t"
			"pop %%rsi\n\t"
			"pop %%rdi\n\t"
			"pop %%rdx\n\t"
			"pop %%rcx\n\t"
			/* Return to kernel via system call */
			"int %[kernel_entry_vector]\n\t"
			/* Kernel Mode */
			"ret_to_kernel:\n\t"
			"mov %[rsp0], %%rsp\n\t"
#ifdef __x86_64__
			/*
			 * Restore SS, as the CPU loads SS with a NULL segment
			 * if handling an interrupt/exception changes the CPL.
			 */
			"mov %[kernel_ds], %%ss\n\t"
#endif
			:
			"+a"(rax),
			[rsp0]"=m"(tss[0].rsp0)
			:
			[arg1]"m"(arg1),
			[arg2]"m"(arg2),
			[arg3]"m"(arg3),
			[arg4]"m"(arg4),
			[func]"m"(func),
			[user_ds]"i"(USER_DS),
			[user_cs]"i"(USER_CS),
			[kernel_ds]"rm"(KERNEL_DS),
			[user_stack_top]"r"(user_stack +
					sizeof(user_stack)),
			[kernel_entry_vector]"i"(RET_TO_KERNEL_IRQ));

	handle_exception(fault_vector, old_ex);

	return rax;
}
