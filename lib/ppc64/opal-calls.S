/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2016 IBM Corporation.
 */

#include <asm/ppc_asm.h>

	.text
	.globl opal_call
opal_call:
	mr	r0,r3
	mr	r3,r4
	mr	r4,r5
	mr	r5,r6
	mr	r6,r7
	mflr	r11
	std	r11,16(r1)
	mfcr	r12
	stw	r12,8(r1)
	std	r2,-8(r1) /* use redzone */

	/* Set opal return address */
	LOAD_REG_ADDR(r11, opal_return)
	mtlr	r11
	mfmsr	r12
	std	r12,-16(r1) /* use redzone */

	/* switch to BE and real-mode when we enter OPAL */
	li	r11,(1 << MSR_LE_BIT) | MSR_IR | MSR_DR
	ori	r11,r11,(1 << MSR_EE_BIT)
	andc	r12,r12,r11
	mtspr	SPR_HSRR1,r12

	/* load the opal call entry point and base */
	LOAD_REG_ADDR(r11, opal)
	ld	r12,8(r11)
	ld	r2,0(r11)
	mtspr	SPR_HSRR0,r12
	hrfid

opal_return:
	FIXUP_ENDIAN
	ld	r12,-16(r1) /* use redzone */
	mtmsrd	r12
	ld	r2,-8(r1) /* use redzone */
	lwz	r11,8(r1);
	ld	r12,16(r1)
	mtcr	r11;
	mtlr	r12
	blr
