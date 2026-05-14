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

#define __SWAP_GPRS			\
	"xchg %%rcx, regs+0x8\n\t"	\
	"xchg %%rdx, regs+0x10\n\t"	\
	"xchg %%rbx, regs+0x18\n\t"	\
	"xchg %%rbp, regs+0x28\n\t"	\
	"xchg %%rsi, regs+0x30\n\t"	\
	"xchg %%rdi, regs+0x38\n\t"	\
	"xchg %%r8, regs+0x40\n\t"	\
	"xchg %%r9, regs+0x48\n\t"	\
	"xchg %%r10, regs+0x50\n\t"	\
	"xchg %%r11, regs+0x58\n\t"	\
	"xchg %%r12, regs+0x60\n\t"	\
	"xchg %%r13, regs+0x68\n\t"	\
	"xchg %%r14, regs+0x70\n\t"	\
	"xchg %%r15, regs+0x78\n\t"

#define SWAP_GPRS			\
	"xchg %%rax, regs+0x0\n\t"	\
	__SWAP_GPRS

#endif /* _x86_VIRT_H_ */
