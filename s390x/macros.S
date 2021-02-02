/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x assembly macros
 *
 * Copyright (c) 2017 Red Hat Inc
 * Copyright (c) 2020, 2021 IBM Corp.
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
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
	/* Allocate a full stack frame */
	slgfi   %r15, STACK_FRAME_INT_SIZE
	/* Store registers r0 to r14 on the stack */
	stmg    %r2, %r15, STACK_FRAME_INT_GRS0(%r15)
	stg     %r0, STACK_FRAME_INT_GRS1(%r15)
	stg     %r1, STACK_FRAME_INT_GRS1 + 8(%r15)
	/* Store the gr15 value before we allocated the new stack */
	lgr     %r0, %r15
	algfi   %r0, STACK_FRAME_INT_SIZE
	stg     %r0, 13 * 8 + STACK_FRAME_INT_GRS0(%r15)
	stg     %r0, STACK_FRAME_INT_BACKCHAIN(%r15)
	/*
	 * Store CR0 and load initial CR0 so AFP is active and we can
	 * access all fprs to save them.
	 */
	stctg   %c0,%c15,STACK_FRAME_INT_CRS(%r15)
	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* Save fp register on stack: offset to SP is multiple of reg number */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8 + STACK_FRAME_INT_FPRS(%r15)
	.endr
	/* Save fpc */
	stfpc	STACK_FRAME_INT_FPC(%r15)
	.endm

/* Restore the register in reverse order */
	.macro RESTORE_REGS_STACK
	/* Restore fpc */
	lfpc	STACK_FRAME_INT_FPC(%r15)
	/* Restore fp register from stack: SP still where it was left */
	/* and offset to SP is a multiple of reg number */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8 + STACK_FRAME_INT_FPRS(%r15)
	.endr
	/* Load CR0 back */
	lctlg	%c0, %c15, STACK_FRAME_INT_CRS(%r15)
	/* Load the registers from stack */
	lg      %r0, STACK_FRAME_INT_GRS1(%r15)
	lg      %r1, STACK_FRAME_INT_GRS1 + 8(%r15)
	lmg     %r2, %r15, STACK_FRAME_INT_GRS0(%r15)
	.endm
