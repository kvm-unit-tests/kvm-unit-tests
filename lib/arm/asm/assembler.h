/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on several files from Linux version v5.10: arch/arm/mm/proc-macros.S,
 * arch/arm/mm/proc-v7.S.
 */

#ifndef __ASSEMBLY__
#error "Only include this from assembly code"
#endif

#ifndef _ASMARM_ASSEMBLER_H_
#define _ASMARM_ASSEMBLER_H_

/*
 * dcache_line_size - get the minimum D-cache line size from the CTR register
 * on ARMv7.
 */
	.macro	dcache_line_size, reg, tmp
	mrc	p15, 0, \tmp, c0, c0, 1		// read ctr
	lsr	\tmp, \tmp, #16
	and	\tmp, \tmp, #0xf		// cache line size encoding
	mov	\reg, #4			// bytes per word
	mov	\reg, \reg, lsl \tmp		// actual cache line size
	.endm

/*
 * Macro to perform a data cache maintenance for the interval
 * [addr, addr + size).
 *
 * 	op:		operation to execute
 * 	domain		domain used in the dsb instruction
 * 	addr:		starting virtual address of the region
 * 	size:		size of the region
 * 	Corrupts:	addr, size, tmp1, tmp2
 */
	.macro dcache_by_line_op op, domain, addr, size, tmp1, tmp2
	dcache_line_size \tmp1, \tmp2
	add	\size, \addr, \size
	sub	\tmp2, \tmp1, #1
	bic	\addr, \addr, \tmp2
9998:
	.ifc	\op, dccimvac
	mcr	p15, 0, \addr, c7, c14, 1
	.else
	.err
	.endif
	add	\addr, \addr, \tmp1
	cmp	\addr, \size
	blo	9998b
	dsb	\domain
	.endm

#endif	/* _ASMARM_ASSEMBLER_H_ */
