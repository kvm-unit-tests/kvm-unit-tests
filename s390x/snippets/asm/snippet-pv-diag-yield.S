/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Diagnose 0x44 and 0x9c snippet used for PV interception tests
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
.section .text

xgr	%r0, %r0
xgr	%r1, %r1
diag	0,0,0x44
lghi	%r1, 42
diag	1,0,0x9c
