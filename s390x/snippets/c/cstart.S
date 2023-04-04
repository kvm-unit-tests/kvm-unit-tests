/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Start assembly for snippets
 *
 * Copyright (c) 2021 IBM Corp.
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/sigp.h>

.section .init
	.globl start
start:
	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* XOR all registers with themselves to clear them fully. */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14
	xgr \i,\i
	.endr
	sam64
	/* 0x3000 is the stack page for now */
	larl	%r15, stackptr
	brasl	%r14, main
	/*
	 * If main() returns, we stop the CPU with the code below. We also
	 * route some functions that are required by the libc (but not usable
	 * from snippets) to the CPU stop code below, so that snippets can
	 * still be linked against the libc code (to use non-related functions
	 * like memset() etc.)
	 */
.global puts
.global exit
puts:
exit:
	/* For now let's only use cpu 0 in snippets so this will always work. */
	xgr	%r0, %r0
	sigp    %r2, %r0, SIGP_STOP

	.align 8
initial_cr0:
	/* enable AFP-register control, so FP regs (+BFP instr) can be used */
	.quad	0x0000000000040000
