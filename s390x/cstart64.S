/*
 * s390x startup code
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#include <asm/asm-offsets.h>

.section .init

/* entry point - for KVM + TCG we directly start in 64 bit mode */
	.globl start
start:
	/* setup stack */
	larl	%r15, stacktop
	/* setup initial PSW mask + control registers*/
	larl	%r1, initital_psw
	lpswe	0(%r1)
init_psw_cont:
	/* setup pgm interrupt handler */
	larl	%r1, pgm_int_psw
	mvc	GEN_LC_PGM_NEW_PSW(16), 0(%r1)
	/* setup cr0, enabling e.g. AFP-register control */
	larl	%r1, initital_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* call setup() */
	brasl	%r14, setup
	/* forward test parameter */
	larl	%r2, __argc
	llgf	%r2, 0(%r2)
	larl	%r3, __argv
	/* call to main() */
	brasl	%r14, main
	/* forward exit code */
	lgr	%r3, %r2
	/* call exit() */
	j exit

pgm_int:
	/* save grs 0-15 */
	stmg	%r0, %r15, GEN_LC_SW_INT_GRS
	/* save fprs 0-15 + fpc */
	larl	%r1, GEN_LC_SW_INT_FPRS
	std	%f0, 0(%r1)
	std	%f1, 8(%r1)
	std	%f2, 16(%r1)
	std	%f3, 24(%r1)
	std	%f4, 32(%r1)
	std	%f5, 40(%r1)
	std	%f6, 48(%r1)
	std	%f7, 56(%r1)
	std	%f8, 64(%r1)
	std	%f9, 72(%r1)
	std	%f10, 80(%r1)
	std	%f11, 88(%r1)
	std	%f12, 96(%r1)
	std	%f13, 104(%r1)
	std	%f14, 112(%r1)
	std	%f15, 120(%r1)
	stfpc	GEN_LC_SW_INT_FPC
	/* call our c handler */
	brasl	%r14, handle_pgm_int
	/* restore fprs 0-15 + fpc */
	larl	%r1, GEN_LC_SW_INT_FPRS
	ld	%f0, 0(%r1)
	ld	%f1, 8(%r1)
	ld	%f2, 16(%r1)
	ld	%f3, 24(%r1)
	ld	%f4, 32(%r1)
	ld	%f5, 40(%r1)
	ld	%f6, 48(%r1)
	ld	%f7, 56(%r1)
	ld	%f8, 64(%r1)
	ld	%f9, 72(%r1)
	ld	%f10, 80(%r1)
	ld	%f11, 88(%r1)
	ld	%f12, 96(%r1)
	ld	%f13, 104(%r1)
	ld	%f14, 112(%r1)
	ld	%f15, 120(%r1)
	lfpc	GEN_LC_SW_INT_FPC
	/* restore grs 0-15 */
	lmg	%r0, %r15, GEN_LC_SW_INT_GRS
	lpswe	GEN_LC_PGM_OLD_PSW

	.align	8
initital_psw:
	.quad	0x0000000180000000, init_psw_cont
pgm_int_psw:
	.quad	0x0000000180000000, pgm_int
initital_cr0:
	/* enable AFP-register control, so FP regs (+BFP instr) can be used */
	.quad	0x0000000000040000
