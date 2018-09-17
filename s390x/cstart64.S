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
	larl	%r15, stackptr
	/* setup initial PSW mask + control registers*/
	larl	%r1, initial_psw
	lpswe	0(%r1)
init_psw_cont:
	/* setup pgm interrupt handler */
	larl	%r1, pgm_int_psw
	mvc	GEN_LC_PGM_NEW_PSW(16), 0(%r1)
	/* setup ext interrupt handler */
	larl	%r1, ext_int_psw
	mvc	GEN_LC_EXT_NEW_PSW(16), 0(%r1)
	/* setup mcck interrupt handler */
	larl	%r1, mcck_int_psw
	mvc	GEN_LC_MCCK_NEW_PSW(16), 0(%r1)
	/* setup io interrupt handler */
	larl	%r1, ext_int_psw
	mvc	GEN_LC_IO_NEW_PSW(16), 0(%r1)
	/* setup svc interrupt handler */
	larl	%r1, mcck_int_psw
	mvc	GEN_LC_SVC_NEW_PSW(16), 0(%r1)
	/* setup cr0, enabling e.g. AFP-register control */
	larl	%r1, initial_cr0
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

	.macro SAVE_REGS
	/* save grs 0-15 */
	stmg	%r0, %r15, GEN_LC_SW_INT_GRS
	/* save cr0 */
	stctg	%c0, %c0, GEN_LC_SW_INT_CR0
	/* load initial cr0 again */
	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* save fprs 0-15 + fpc */
	la	%r1, GEN_LC_SW_INT_FPRS
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
	.endm

	.macro RESTORE_REGS
	/* restore fprs 0-15 + fpc */
	la	%r1, GEN_LC_SW_INT_FPRS
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
	/* restore cr0 */
	lctlg	%c0, %c0, GEN_LC_SW_INT_CR0
	/* restore grs 0-15 */
	lmg	%r0, %r15, GEN_LC_SW_INT_GRS
	.endm

.section .text
pgm_int:
	SAVE_REGS
	brasl	%r14, handle_pgm_int
	RESTORE_REGS
	lpswe	GEN_LC_PGM_OLD_PSW

ext_int:
	SAVE_REGS
	brasl	%r14, handle_ext_int
	RESTORE_REGS
	lpswe	GEN_LC_EXT_OLD_PSW

mcck_int:
	SAVE_REGS
	brasl	%r14, handle_mcck_int
	RESTORE_REGS
	lpswe	GEN_LC_MCCK_OLD_PSW

io_int:
	SAVE_REGS
	brasl	%r14, handle_io_int
	RESTORE_REGS
	lpswe	GEN_LC_IO_OLD_PSW

svc_int:
	SAVE_REGS
	brasl	%r14, handle_svc_int
	RESTORE_REGS
	lpswe	GEN_LC_SVC_OLD_PSW

	.align	8
initial_psw:
	.quad	0x0000000180000000, init_psw_cont
pgm_int_psw:
	.quad	0x0000000180000000, pgm_int
ext_int_psw:
	.quad	0x0000000180000000, ext_int
mcck_int_psw:
	.quad	0x0000000180000000, mcck_int
io_int_psw:
	.quad	0x0000000180000000, io_int
svc_int_psw:
	.quad	0x0000000180000000, svc_int
initial_cr0:
	/* enable AFP-register control, so FP regs (+BFP instr) can be used */
	.quad	0x0000000000040000
