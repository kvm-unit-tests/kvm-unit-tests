/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Diagnose 0x308 snippet used for PV IPL and reset testing
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>
.section .text

/*
 * Entry
 * Execute the diag500 which will set the diag 308 subcode in gr2
 */
diag	0, 0, 0x500

/*
 * A valid PGM new PSW can be a real problem since we never fall out
 * of SIE and therefore effectively loop forever. 0 is a valid PSW
 * therefore we re-use the reset_psw as this has the short PSW
 * bit set which is invalid for a long PSW like the exception new
 * PSWs.
 *
 * For subcode 0/1 there are no PGMs to consider.
 */
lgrl   %r5, reset_psw
stg    %r5, GEN_LC_PGM_NEW_PSW

/* Set up the reset psw at 0x0 */
lgrl	%r5, reset_psw
larl	%r6, done
ogr	%r5, %r6
stg	%r5, 0

/* Diag 308, subcode is in gr2 */
diag	%r0, %r2, 0x308

/* Should never be executed because of the reset PSW */
diag	0, 0, 0x44

/* Pass on a special value indicating success */
done:
lghi	%r1, 42
diag	%r1, 0, 0x9c


	.align	8
reset_psw:
	.quad	0x0008000180000000
