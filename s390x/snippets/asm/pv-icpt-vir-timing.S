/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Sets a cpu timer which the host can manipulate to check if it will
 * receive a validity
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
.section .text
larl	%r1, time_val
spt	0 (%r1)
diag    0, 0, 0x44
lghi	%r1, 42
diag	1, 0, 0x9c


.align 8
time_val:
	.quad 0x280de80000
