/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x SIE assembly library
 *
 * Copyright (c) 2019 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>

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

	stctg	%c1, %c1, SIE_SAVEAREA_HOST_ASCE(%r3)
	lctlg	%c1, %c1, SIE_SAVEAREA_GUEST_ASCE(%r3)

	# Store scb and save_area pointer into stack frame
	stg	%r2,__SF_SIE_CONTROL(%r15)	# save control block pointer
	stg	%r3,__SF_SIE_SAVEAREA(%r15)	# save guest register save area
.globl sie_entry_gregs
sie_entry_gregs:
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

	# Restore the host asce
	lctlg	%c1, %c1, SIE_SAVEAREA_HOST_ASCE(%r14)

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
.globl sie_exit_gregs
sie_exit_gregs:
	br	%r14
