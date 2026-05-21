#ifndef _x86_VIRT_H_
#define _x86_VIRT_H_

#include "libcflat.h"
#include "processor.h"
#include "smp.h"

static inline struct guest_regs *this_cpu_guest_regs(void)
{
	return (void *)rdmsr(MSR_GS_BASE) + offsetof_percpu(guest_regs);
}

#define GUEST_REG_OFFSET(name) \
	[off_##name] "i" (offsetof_percpu(guest_regs) + offsetof(struct guest_regs, name))

#define GUEST_REGS_OFFSETS	\
	GUEST_REG_OFFSET(rax),	\
	GUEST_REG_OFFSET(rcx),	\
	GUEST_REG_OFFSET(rdx),	\
	GUEST_REG_OFFSET(rbx),	\
	GUEST_REG_OFFSET(cr2),	\
	GUEST_REG_OFFSET(rbp),	\
	GUEST_REG_OFFSET(rsi),	\
	GUEST_REG_OFFSET(rdi),	\
	GUEST_REG_OFFSET(r8),	\
	GUEST_REG_OFFSET(r9),	\
	GUEST_REG_OFFSET(r10),	\
	GUEST_REG_OFFSET(r11),	\
	GUEST_REG_OFFSET(r12),	\
	GUEST_REG_OFFSET(r13),	\
	GUEST_REG_OFFSET(r14),	\
	GUEST_REG_OFFSET(r15),	\
	GUEST_REG_OFFSET(rflags)

#define GUEST_REG(name) \
	xxstr(%%gs:%c[off_##name])

#define SWAP_REG(name) \
	"xchg %%" xxstr(name) "," GUEST_REG(name) "\n\t"

#define __SWAP_GPRS		\
	SWAP_REG(rcx)		\
	SWAP_REG(rdx)		\
	SWAP_REG(rbx)		\
	SWAP_REG(rbp)		\
	SWAP_REG(rsi)		\
	SWAP_REG(rdi)		\
	SWAP_REG(r8)		\
	SWAP_REG(r9)		\
	SWAP_REG(r10)		\
	SWAP_REG(r11)		\
	SWAP_REG(r12)		\
	SWAP_REG(r13)		\
	SWAP_REG(r14)		\
	SWAP_REG(r15)

#define SWAP_GPRS		\
	SWAP_REG(rax)		\
	__SWAP_GPRS

#endif /* _x86_VIRT_H_ */
