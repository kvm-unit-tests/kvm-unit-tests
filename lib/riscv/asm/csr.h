/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_CSR_H_
#define _ASMRISCV_CSR_H_
#include <linux/const.h>

#define CSR_SSTATUS		0x100
#define CSR_STVEC		0x105
#define CSR_SSCRATCH		0x140
#define CSR_SEPC		0x141
#define CSR_SCAUSE		0x142
#define CSR_STVAL		0x143

/* Exception cause high bit - is an interrupt if set */
#define CAUSE_IRQ_FLAG		(_AC(1, UL) << (__riscv_xlen - 1))

/* Exception causes */
#define EXC_INST_MISALIGNED	0
#define EXC_INST_ACCESS		1
#define EXC_INST_ILLEGAL	2
#define EXC_BREAKPOINT		3
#define EXC_LOAD_MISALIGNED	4
#define EXC_LOAD_ACCESS		5
#define EXC_STORE_MISALIGNED	6
#define EXC_STORE_ACCESS	7
#define EXC_SYSCALL		8
#define EXC_HYPERVISOR_SYSCALL	9
#define EXC_SUPERVISOR_SYSCALL	10
#define EXC_INST_PAGE_FAULT	12
#define EXC_LOAD_PAGE_FAULT	13
#define EXC_STORE_PAGE_FAULT	15
#define EXC_INST_GUEST_PAGE_FAULT	20
#define EXC_LOAD_GUEST_PAGE_FAULT	21
#define EXC_VIRTUAL_INST_FAULT		22
#define EXC_STORE_GUEST_PAGE_FAULT	23

#ifndef __ASSEMBLY__

#define csr_swap(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrrw %0, " __ASM_STR(csr) ", %1"\
				: "=r" (__v) : "rK" (__v)	\
				: "memory");			\
	__v;							\
})

#define csr_read(csr)						\
({								\
	register unsigned long __v;				\
	__asm__ __volatile__ ("csrr %0, " __ASM_STR(csr)	\
				: "=r" (__v) :			\
				: "memory");			\
	__v;							\
})

#define csr_write(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrw " __ASM_STR(csr) ", %0"	\
				: : "rK" (__v)			\
				: "memory");			\
})

#define csr_read_set(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrrs %0, " __ASM_STR(csr) ", %1"\
				: "=r" (__v) : "rK" (__v)	\
				: "memory");			\
	__v;							\
})

#define csr_set(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrs " __ASM_STR(csr) ", %0"	\
				: : "rK" (__v)			\
				: "memory");			\
})

#define csr_read_clear(csr, val)				\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrrc %0, " __ASM_STR(csr) ", %1"\
				: "=r" (__v) : "rK" (__v)	\
				: "memory");			\
	__v;							\
})

#define csr_clear(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrc " __ASM_STR(csr) ", %0"	\
				: : "rK" (__v)			\
				: "memory");			\
})

#endif /* !__ASSEMBLY__ */
#endif /* _ASMRISCV_CSR_H_ */
