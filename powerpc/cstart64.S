/*
 * Entry point and assembler functions for ppc64 tests.
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#define __ASSEMBLY__

.section .init

.globl start
start:
	b	halt

.text

.globl halt
halt:
1:	b	1b
