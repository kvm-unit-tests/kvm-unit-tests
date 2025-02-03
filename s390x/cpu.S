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

	.align	8
reset_psw:
	.quad	0x0008000180000000
