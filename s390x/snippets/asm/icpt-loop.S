/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Infinite loop snippet which can be used to test manipulated SIE
 * control block intercepts. E.g. when manipulating the PV handles.
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
.section .text
xgr	%r0, %r0
retry:
diag	0,0,0x44
j 	retry
