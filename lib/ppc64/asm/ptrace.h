#ifndef _ASMPPC64_PTRACE_H_
#define _ASMPPC64_PTRACE_H_

#define KERNEL_REDZONE_SIZE	288
#define STACK_FRAME_OVERHEAD    112     /* size of minimum stack frame */

#ifndef __ASSEMBLER__

#include <asm/reg.h>

struct pt_regs {
	unsigned long gpr[32];
	unsigned long nip;
	unsigned long msr;
	unsigned long ctr;
	unsigned long link;
	unsigned long xer;
	unsigned long ccr;
	unsigned long trap;
	unsigned long _pad; /* stack must be 16-byte aligned */
};

static inline bool regs_is_prefix(volatile struct pt_regs *regs)
{
	return regs->msr & SRR1_PREFIX;
}

static inline void regs_advance_insn(struct pt_regs *regs)
{
	if (regs_is_prefix(regs))
		regs->nip += 8;
	else
		regs->nip += 4;
}

#define STACK_INT_FRAME_SIZE    (sizeof(struct pt_regs) + \
				 STACK_FRAME_OVERHEAD + KERNEL_REDZONE_SIZE)

#endif /* __ASSEMBLER__ */

#endif /* _ASMPPC64_PTRACE_H_ */
