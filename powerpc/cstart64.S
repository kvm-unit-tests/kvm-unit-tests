/*
 * Entry point and assembler functions for ppc64 tests.
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#define __ASSEMBLY__
#include <asm/hcall.h>

#define LOAD_REG_IMMEDIATE(reg,expr)		\
	lis	reg,(expr)@highest;		\
	ori	reg,reg,(expr)@higher;		\
	rldicr	reg,reg,32,31;			\
	oris	reg,reg,(expr)@h;		\
	ori	reg,reg,(expr)@l;

#define LOAD_REG_ADDR(reg,name)			\
	ld	reg,name@got(r2)

.section .init

.globl start
start:
	LOAD_REG_IMMEDIATE(r1, stackptr)
	LOAD_REG_IMMEDIATE(r2, tocptr)

	/* patch sc1 if needed */
	bl	hcall_have_broken_sc1
	cmpwi	r3, 0
	beq	1f
	LOAD_REG_ADDR(r3, hcall)
	LOAD_REG_IMMEDIATE(r4, SC1_REPLACEMENT)
	stw	r4, 0(r3)

1:	bl	main
	bl	exit
	b	halt

.text
.align 3

.globl hcall
hcall:
	sc	1
	blr

.globl halt
halt:
1:	b	1b
