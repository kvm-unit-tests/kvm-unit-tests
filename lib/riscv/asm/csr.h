/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_CSR_H_
#define _ASMRISCV_CSR_H_
#include <linux/const.h>

#define CSR_SSTATUS		0x100
#define CSR_SIE			0x104
#define CSR_STVEC		0x105
#define CSR_SSCRATCH		0x140
#define CSR_SEPC		0x141
#define CSR_SCAUSE		0x142
#define CSR_STVAL		0x143
#define CSR_SIP			0x144
#define CSR_STIMECMP		0x14d
#define CSR_STIMECMPH		0x15d
#define CSR_SATP		0x180
#define CSR_TIME		0xc01

#define SR_SIE			_AC(0x00000002, UL)
#define SR_SPP			_AC(0x00000100, UL)

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

/* Interrupt causes */
#define IRQ_S_SOFT		1
#define IRQ_VS_SOFT		2
#define IRQ_S_TIMER		5
#define IRQ_VS_TIMER		6
#define IRQ_S_EXT		9
#define IRQ_VS_EXT		10
#define IRQ_S_GEXT		12
#define IRQ_PMU_OVF		13

#define IE_SSIE			(_AC(1, UL) << IRQ_S_SOFT)
#define IE_TIE			(_AC(1, UL) << IRQ_S_TIMER)

#define IP_TIP			IE_TIE

#ifndef __ASSEMBLER__

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

#endif /* !__ASSEMBLER__ */
#endif /* _ASMRISCV_CSR_H_ */
