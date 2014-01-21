/*
 * Boot entry point and assembler functions for armv7 tests.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

.arm

.section .init

.globl start
start:
	/*
	 * bootloader params are in r0-r2
	 * See the kernel doc Documentation/arm/Booting
	 */
	ldr	sp, =stacktop
	bl	setup

	/* run the test */
	ldr	r0, =__argc
	ldr	r0, [r0]
	ldr	r1, =__argv
	bl	main
	bl	exit
	b	halt

.text

.globl halt
halt:
1:	wfi
	b	1b
