/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Diagnose 0x500 snippet used for PV interception tests
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>
#include "macros.S"
.section .text

/* Clean and pre-load registers that are used for diag 500 */
xgr	%r1, %r1
xgr	%r2, %r2
xgr	%r3, %r3
xgr	%r4, %r4
lghi	%r1, 1
lghi	%r2, 2
lghi	%r3, 3
lghi	%r4, 4

/* Let's jump to the next label on a PGM */
SET_PSW_NEW_ADDR 5, next, GEN_LC_PGM_NEW_PSW

/* Execute the diag500 */
diag	0, 0, 0x500

/* Should never be executed because of the PGM */
diag	0, 0, 0x44

/* Execute again to test spec PGM injection*/
next:
lh	%r1, GEN_LC_PGM_INT_CODE
diag	%r1, 0, 0x9c
larl	%r5, done
stg	%r5, GEN_LC_PGM_NEW_PSW + 8
diag	0, 0, 0x500

/* Should never be executed because of the PGM */
diag	0, 0, 0x44

done:
lh	%r1, GEN_LC_PGM_INT_CODE
diag	%r1, 0, 0x9c
