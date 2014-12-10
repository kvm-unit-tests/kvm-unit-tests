/*
 * Boot entry point and assembler functions for aarch64 tests.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#define __ASSEMBLY__
#include <asm/asm-offsets.h>

.section .init

.globl start
start:
	/*
	 * bootloader params are in x0-x3
	 * The physical address of the dtb is in x0, x1-x3 are reserved
	 * See the kernel doc Documentation/arm64/booting.txt
	 */
	adr     x4, stacktop
	mov	sp, x4
	stp	x0, x1, [sp, #-16]!

	/* Enable FP/ASIMD */
	mov	x0, #(3 << 20)
	msr	cpacr_el1, x0

	/* set up exception handling */
//	bl	exceptions_init

	/* complete setup */
	ldp	x0, x1, [sp], #16
	bl	setup

	/* run the test */
	adr	x0, __argc
	ldr	x0, [x0]
	adr	x1, __argv
	bl	main
	bl	exit
	b	halt

.text

.globl halt
halt:
1:	wfi
	b	1b
