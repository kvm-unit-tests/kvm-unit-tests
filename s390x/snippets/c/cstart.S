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
	/* XOR all registers with themselves to clear them fully. */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	xgr \i,\i
	.endr
	/* 0x3000 is the stack page for now */
	lghi	%r15, 0x4000 - 160
	sam64
	brasl	%r14, main
	/* For now let's only use cpu 0 in snippets so this will always work. */
	xgr	%r0, %r0
	sigp    %r2, %r0, SIGP_STOP
