/*
 * s390x startup code
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
.section .init

/* entry point - for KVM + TCG we directly start in 64 bit mode */
	.globl start
start:
	/* setup stack */
	larl	%r15, stacktop
	/* setup initial PSW mask + control registers*/
	larl	%r1, initital_psw
	lpswe	0(%r1)
init_psw_cont:
	larl	%r1, initital_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* call setup() */
	brasl	%r14, setup
	/* forward test parameter */
	larl	%r2, __argc
	llgf	%r2, 0(%r2)
	larl	%r3, __argv
	/* call to main() */
	brasl	%r14, main
	/* forward exit code */
	lgr	%r3, %r2
	/* call exit() */
	j exit

	.align	8
initital_psw:
	.quad	0x0000000180000000, init_psw_cont
initital_cr0:
	/* enable AFP-register control, so FP regs (+BFP instr) can be used */
	.quad	0x0000000000040000
