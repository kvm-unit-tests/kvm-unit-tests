// EABI ldivmod and uldivmod implementation based on libcompiler-rt
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses.

	.syntax unified
	.align 2
	.globl __aeabi_uldivmod
	.type __aeabi_uldivmod, %function
__aeabi_uldivmod:
	push	{r11, lr}
	sub	sp, sp, #16
	add	r12, sp, #8
	str	r12, [sp]                // third argument to __udivmoddi4
	bl	__udivmoddi4
	ldr	r2, [sp, #8]             // remainder returned in r2-r3
	ldr	r3, [sp, #12]
	add	sp, sp, #16
	pop	{r11, pc}

	.globl __aeabi_ldivmod
	.type __aeabi_ldivmod, %function
__aeabi_ldivmod:
	push	{r11, lr}
	sub	sp, sp, #16
	add	r12, sp, #8
	str	r12, [sp]                // third argument to __divmoddi4
	bl	__divmoddi4
	ldr	r2, [sp, #8]             // remainder returned in r2-r3
	ldr	r3, [sp, #12]
	add	sp, sp, #16
	pop	{r11, pc}
