/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_BUG_H_
#define _ASMRISCV_BUG_H_

#ifndef __ASSEMBLER__

static inline void bug(void)
{
	asm volatile("ebreak");
}

#else

.macro bug
	ebreak
.endm

#endif

#endif /* _ASMRISCV_BUG_H_ */
