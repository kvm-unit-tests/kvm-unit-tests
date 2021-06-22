/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x assembly library
 *
 * Copyright (c) 2019 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>
#include <asm/sigp.h>

#include "macros.S"

/*
 * load_reset calling convention:
 * %r2 subcode (0 or 1)
 */
.globl diag308_load_reset
diag308_load_reset:
	SAVE_REGS_STACK
	/* Backup current PSW mask, as we have to restore it on success */
	epsw	%r0, %r1
	st	%r0, GEN_LC_SW_INT_PSW
	st	%r1, GEN_LC_SW_INT_PSW + 4
	/* Load reset psw mask (short psw, 64 bit) */
	lg	%r0, reset_psw
	/* Load the success label address */
	larl    %r1, 0f
	/* Or it to the mask */
	ogr	%r0, %r1
	/* Store it at the reset PSW location (real 0x0) */
	stg	%r0, 0
	stg     %r15, GEN_LC_SW_INT_GRS + 15 * 8
	/* Do the reset */
	diag    %r0,%r2,0x308
	/* Failure path */
	xgr	%r2, %r2
	br	%r14
	/* Success path */
	/* load a cr0 that has the AFP control bit which enables all FPRs */
0:	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	lg      %r15, GEN_LC_SW_INT_GRS + 15 * 8
	RESTORE_REGS_STACK
	lhi	%r2, 1
	larl	%r0, 1f
	stg	%r0, GEN_LC_SW_INT_PSW + 8
	lpswe	GEN_LC_SW_INT_PSW
1:	br	%r14

/* Sets up general registers and cr0 when a new cpu is brought online. */
.globl smp_cpu_setup_state
smp_cpu_setup_state:
	xgr	%r1, %r1
	lmg     %r0, %r15, GEN_LC_SW_INT_GRS
	lctlg   %c0, %c0, GEN_LC_SW_INT_CRS
	/* We should only go once through cpu setup and not for every restart */
	stg	%r14, GEN_LC_RESTART_NEW_PSW + 8
	larl	%r14, 0f
	lpswe	GEN_LC_SW_INT_PSW
	/* If the function returns, just loop here */
0:	j	0

/*
 * sie64a calling convention:
 * %r2 pointer to sie control block
 * %r3 guest register save area
 */
.globl sie64a
sie64a:
	# Save host grs, fprs, fpc
	stmg	%r0,%r14,SIE_SAVEAREA_HOST_GRS(%r3)	# save kernel registers
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8  + SIE_SAVEAREA_HOST_FPRS(%r3)
	.endr
	stfpc	SIE_SAVEAREA_HOST_FPC(%r3)

	# Store scb and save_area pointer into stack frame
	stg	%r2,__SF_SIE_CONTROL(%r15)	# save control block pointer
	stg	%r3,__SF_SIE_SAVEAREA(%r15)	# save guest register save area

	# Load guest's gprs, fprs and fpc
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8 + SIE_SAVEAREA_GUEST_FPRS(%r3)
	.endr
	lfpc	SIE_SAVEAREA_GUEST_FPC(%r3)
	lmg	%r0,%r13,SIE_SAVEAREA_GUEST_GRS(%r3)

	# Move scb ptr into r14 for the sie instruction
	lg	%r14,__SF_SIE_CONTROL(%r15)

.globl sie_entry
sie_entry:
	sie	0(%r14)
	nopr	7
	nopr	7
	nopr	7

.globl sie_exit
sie_exit:
	# Load guest register save area
	lg	%r14,__SF_SIE_SAVEAREA(%r15)

	# Store guest's gprs, fprs and fpc
	stmg	%r0,%r13,SIE_SAVEAREA_GUEST_GRS(%r14)	# save guest gprs 0-13
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8  + SIE_SAVEAREA_GUEST_FPRS(%r14)
	.endr
	stfpc	SIE_SAVEAREA_GUEST_FPC(%r14)

	# Restore host's gprs, fprs and fpc
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8 + SIE_SAVEAREA_HOST_FPRS(%r14)
	.endr
	lfpc	SIE_SAVEAREA_HOST_FPC(%r14)
	lmg	%r0,%r14,SIE_SAVEAREA_HOST_GRS(%r14)	# restore kernel registers

	br	%r14

	.align	8
reset_psw:
	.quad	0x0008000180000000
