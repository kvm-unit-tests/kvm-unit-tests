/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Intercept 112 PV snippet
 *
 * We setup and share a prefix at 0x0 and 0x8000 which the hypervisor
 * test will try to export and then execute a SIE entry which
 * should result in a 112 SIE intercept.
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>

.section .text
xgr	%r0, %r0
xgr	%r1, %r1

/* Let's tell the hypervisor we're ready to start */
diag	0,0,0x44

/*
 * Hypervisor will export the lowcore and try a SIE entry which should
 * result in a 112. It will then import the lowcore again and we
 * should continue with the code below.
 */

/* Share the lowcore */
larl	%r1, share
.insn rrf,0xB9A40000,0,1,0,0
xgr	%r1, %r1

/*  Let's tell the hypervisor we're ready to start shared testing */
diag	0,0,0x44

/* Host: icpt:  PV instruction diag 0x44 */
/* Host: icpt:  112 */

/* Copy the invalid PGM new PSW to the new lowcore */
larl	%r1, prfx
l	%r2, 0(%r1)
mvc     GEN_LC_PGM_NEW_PSW(16, %r2), GEN_LC_PGM_NEW_PSW(%r0)

/* Change the prefix to 0x8000 and re-try */
xgr	%r1, %r1
xgr	%r2, %r2
larl	%r2, prfx
spx	0(%r2)

/* Host: icpt:  PV instruction notification SPX*/
/* Host: icpt:  112 */

/* Share the new lowcore */
larl	%r3, share_addr
stg	%r2, 0(%r3)
larl	%r2, share
.insn rrf,0xB9A40000,0,2,0,0

/* Let's tell the hypervisor we're ready to start shared testing */
diag	0,0,0x44

/* Host: icpt:  PV instruction diag 0x44 */
/* Host: icpt:  112 */

/* Test re-entry */
lghi	%r1, 42
diag	1,0,0x9c

/* Host: icpt:  PV instruction diag 0x9c */

.align 8
share:
	.quad 0x0030100000000000
	.quad 0x0, 0x0, 0x0
share_addr:
	.quad 0x0
	.quad 0x0
.align 4
prfx:
	.long 0x00008000
