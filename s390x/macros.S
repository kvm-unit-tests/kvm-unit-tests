/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x assembly macros
 *
 * Copyright (c) 2017 Red Hat Inc
 * Copyright (c) 2020 IBM Corp.
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *  David Hildenbrand <david@redhat.com>
 */
#include <asm/asm-offsets.h>
	.macro SAVE_REGS
	/* save grs 0-15 */
	stmg	%r0, %r15, GEN_LC_SW_INT_GRS
	/* save crs 0-15 */
	stctg	%c0, %c15, GEN_LC_SW_INT_CRS
	/* load a cr0 that has the AFP control bit which enables all FPRs */
	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* save fprs 0-15 + fpc */
	la	%r1, GEN_LC_SW_INT_FPRS
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8(%r1)
	.endr
	stfpc	GEN_LC_SW_INT_FPC
	.endm

	.macro RESTORE_REGS
	/* restore fprs 0-15 + fpc */
	la	%r1, GEN_LC_SW_INT_FPRS
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8(%r1)
	.endr
	lfpc	GEN_LC_SW_INT_FPC
	/* restore crs 0-15 */
	lctlg	%c0, %c15, GEN_LC_SW_INT_CRS
	/* restore grs 0-15 */
	lmg	%r0, %r15, GEN_LC_SW_INT_GRS
	.endm

/* Save registers on the stack (r15), so we can have stacked interrupts. */
	.macro SAVE_REGS_STACK
	/* Allocate a stack frame for 15 general registers */
	slgfi   %r15, 15 * 8
	/* Store registers r0 to r14 on the stack */
	stmg    %r0, %r14, 0(%r15)
	/* Allocate a stack frame for 16 floating point registers */
	/* The size of a FP register is the size of an double word */
	slgfi   %r15, 16 * 8
	/* Save fp register on stack: offset to SP is multiple of reg number */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8(%r15)
	.endr
	/* Save fpc, but keep stack aligned on 64bits */
	slgfi   %r15, 8
	efpc	%r0
	stg	%r0, 0(%r15)
	.endm

/* Restore the register in reverse order */
	.macro RESTORE_REGS_STACK
	/* Restore fpc */
	lfpc	0(%r15)
	algfi	%r15, 8
	/* Restore fp register from stack: SP still where it was left */
	/* and offset to SP is a multiple of reg number */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8(%r15)
	.endr
	/* Now that we're done, rewind the stack pointer by 16 double word */
	algfi   %r15, 16 * 8
	/* Load the registers from stack */
	lmg     %r0, %r14, 0(%r15)
	/* Rewind the stack by 15 double word */
	algfi   %r15, 15 * 8
	.endm
