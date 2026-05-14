#ifndef _x86_VIRT_H_
#define _x86_VIRT_H_

#include "libcflat.h"

struct guest_regs {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	/*
	 * Use RSP's index to hold CR2, as RSP isn't manually context switched
	 * by software in any relevant flows.
	 */
	u64 cr2;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rflags;
};

extern struct guest_regs regs;

#define GUEST_REG_OFFSET(name) \
	[off_##name] "i" (offsetof(struct guest_regs, name))

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
	xxstr(regs+%c[off_##name])

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
