/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_ASM_H_
#define _ASMRISCV_ASM_H_

#if __riscv_xlen == 64
#define __REG_SEL(a, b) a
#elif __riscv_xlen == 32
#define __REG_SEL(a, b) b
#else
#error "Unexpected __riscv_xlen"
#endif

#define REG_L	__REG_SEL(ld, lw)
#define REG_S	__REG_SEL(sd, sw)
#define SZREG	__REG_SEL(8, 4)

/* ASMARR() may be used with arrays of longs */
#define ASMARR(reg, idx)	((idx) * SZREG)(reg)

#define FP_SIZE 16

#endif /* _ASMRISCV_ASM_H_ */
