/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on the file arch/arm64/include/asm/assembled.h from Linux v5.10, which
 * in turn is based on arch/arm/include/asm/assembler.h and
 * arch/arm/mm/proc-macros.S
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __ASSEMBLY__
#error "Only include this from assembly code"
#endif

#ifndef _ASMARM64_ASSEMBLER_H_
#define _ASMARM64_ASSEMBLER_H_

/*
 * raw_dcache_line_size - get the minimum D-cache line size on this CPU
 * from the CTR register.
 */
	.macro	raw_dcache_line_size, reg, tmp
	mrs	\tmp, ctr_el0			// read CTR
	ubfx	\tmp, \tmp, #16, #4		// cache line size encoding
	mov	\reg, #4			// bytes per word
	lsl	\reg, \reg, \tmp		// actual cache line size
	.endm

/*
 * Macro to perform a data cache maintenance for the interval
 * [addr, addr + size). Use the raw value for the dcache line size because
 * kvm-unit-tests has no concept of scheduling.
 *
 * 	op:		operation passed to dc instruction
 * 	domain:		domain used in dsb instruciton
 * 	addr:		starting virtual address of the region
 * 	size:		size of the region
 * 	Corrupts:	addr, size, tmp1, tmp2
 */

	.macro dcache_by_line_op op, domain, addr, size, tmp1, tmp2
	raw_dcache_line_size \tmp1, \tmp2
	add	\size, \addr, \size
	sub	\tmp2, \tmp1, #1
	bic	\addr, \addr, \tmp2
9998:
	dc	\op, \addr
	add	\addr, \addr, \tmp1
	cmp	\addr, \size
	b.lo	9998b
	dsb	\domain
	.endm

#endif	/* _ASMARM64_ASSEMBLER_H_ */
