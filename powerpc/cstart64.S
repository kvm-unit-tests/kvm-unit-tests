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

/*
 * start is the entry point. r3 points to the DTB
 */
.globl start
start:
	/*
	 * We were loaded at QEMU's kernel load address, but we're not
	 * allowed to link there due to how QEMU deals with linker VMAs,
	 * so we just linked at zero. This means the first thing to do is
	 * to find our stack and toc, and then do a relocate.
	 */
	bl	0f
0:	mflr	r31
	subi	r31, r31, 0b - start    /* QEMU's kernel load address */
	ld	r1, (p_stack - start)(r31)
	ld	r2, (p_toc - start)(r31)
	add	r1, r1, r31
	add	r2, r2, r31

	/* save DTB pointer */
	std	r3, 56(r1)

	/*
	 * Call relocate. relocate is C code, but careful to not use
	 * any global references, as they may use absolute addresses,
	 * which are, obviously, not yet relocated.
	 */
	mr	r3, r31
	ld	r4, (p_dyn - start)(r31)
	add	r4, r4, r31
	bl	relocate

	/* patch sc1 if needed */
	bl	hcall_have_broken_sc1
	cmpwi	r3, 0
	beq	1f
	LOAD_REG_ADDR(r3, hcall)
	LOAD_REG_IMMEDIATE(r4, SC1_REPLACEMENT)
	stw	r4, 0(r3)

	/* complete setup */
1:	ld	r3, 56(r1)
	bl	setup

	/* run the test */
	LOAD_REG_ADDR(r5, __argc)
	LOAD_REG_ADDR(r4, __argv)
	lwz	r3, 0(r5)
	bl	main
	bl	exit
	b	halt

.align 3
p_stack:	.llong  stackptr
p_toc:		.llong  tocptr
p_dyn:		.llong  dynamic_start

.text
.align 3

.globl hcall
hcall:
	sc	1
	blr

.globl halt
halt:
1:	b	1b
