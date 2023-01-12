/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Commonly used assembly macros
 *
 * Copyright (c) 2022 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>

/*
 * Writes a PSW to addr_psw, useful for exception PSWs in lowcore
 *
 * reg is the scratch register used for temporary storage, it's NOT restored
 * The psw address part is defined via psw_new_addr
 * The psw mask part is always 64 bit
 */
.macro SET_PSW_NEW_ADDR reg, psw_new_addr, addr_psw
larl	\reg, psw_mask_64
mvc	\addr_psw(8,%r0), 0(\reg)
larl	\reg, \psw_new_addr
stg	\reg, \addr_psw + 8
.endm

.section .rodata
psw_mask_64:
	.quad	0x0000000180000000
