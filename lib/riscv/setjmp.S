/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm.h>

.section .text

.balign 4
.global setjmp
setjmp:
	REG_S	ra, (0 * SZREG)(a0)
	REG_S	s0, (1 * SZREG)(a0)
	REG_S	s1, (2 * SZREG)(a0)
	REG_S	s2, (3 * SZREG)(a0)
	REG_S	s3, (4 * SZREG)(a0)
	REG_S	s4, (5 * SZREG)(a0)
	REG_S	s5, (6 * SZREG)(a0)
	REG_S	s6, (7 * SZREG)(a0)
	REG_S	s7, (8 * SZREG)(a0)
	REG_S	s8, (9 * SZREG)(a0)
	REG_S	s9, (10 * SZREG)(a0)
	REG_S	s10, (11 * SZREG)(a0)
	REG_S	s11, (12 * SZREG)(a0)
	REG_S	sp, (13 * SZREG)(a0)
	REG_S	gp, (14 * SZREG)(a0)
	REG_S	tp, (15 * SZREG)(a0)
	li	a0, 0
	ret

.balign 4
.global longjmp
longjmp:
	REG_L	ra, (0 * SZREG)(a0)
	REG_L	s0, (1 * SZREG)(a0)
	REG_L	s1, (2 * SZREG)(a0)
	REG_L	s2, (3 * SZREG)(a0)
	REG_L	s3, (4 * SZREG)(a0)
	REG_L	s4, (5 * SZREG)(a0)
	REG_L	s5, (6 * SZREG)(a0)
	REG_L	s6, (7 * SZREG)(a0)
	REG_L	s7, (8 * SZREG)(a0)
	REG_L	s8, (9 * SZREG)(a0)
	REG_L	s9, (10 * SZREG)(a0)
	REG_L	s10, (11 * SZREG)(a0)
	REG_L	s11, (12 * SZREG)(a0)
	REG_L	sp, (13 * SZREG)(a0)
	REG_L	gp, (14 * SZREG)(a0)
	REG_L	tp, (15 * SZREG)(a0)
	seqz	a0, a1
	add	a0, a0, a1
	ret
