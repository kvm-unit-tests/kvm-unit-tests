/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x startup code
 *
 * Copyright (c) 2017 Red Hat Inc
 * Copyright (c) 2019 IBM Corp.
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <asm/asm-offsets.h>
#include <asm/sigp.h>

#include "macros.S"
.section .init

/*
 * Short init between 0x10000 and 0x10480 and then jump to 0x11000.
 * 0x10480 - 0x11000 are written to by bootloader.
 *
 * For KVM and TCG kernel boot we are in 64 bit z/Arch mode.
 * When booting from disk the initial short psw is in 31 bit mode.
 * When running under LPAR or z/VM, we might start in 31 bit and esam mode.
 */
	.globl start
start:
	/* Switch to z/Architecture mode and 64-bit */
	slr     %r0, %r0		# Set cpuid to zero
	lhi     %r1, 2			# mode 2 = esame
	sigp    %r1, %r0, SIGP_SET_ARCHITECTURE
	/* XOR all registers with themselves to clear them fully. */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	xgr \i,\i
	.endr
	sam64				# Set addressing mode to 64 bit
	/* setup stack */
	larl	%r15, stackptr
	/* setup initial PSW mask + control registers*/
	larl	%r1, initial_psw
	lpswe	0(%r1)
clear_bss_start:
	larl 	%r2, __bss_start
	larl 	%r3, __bss_end
	slgr 	%r3, %r2		# Get sizeof bss
	aghi 	%r3,-1
	srlg 	%r4,%r3,8		# Calc number of 256 byte chunks
	ltgr 	%r4,%r4
	lgr 	%r1,%r2
	jz	clear_bss_remainder		# If none, clear remaining bytes
clear_bss_loop:
	xc	0(256,%r1), 0(%r1)	# Clear 256 byte chunks via xor
	la	%r1, 256(%r1)
	brctg 	%r4, clear_bss_loop
clear_bss_remainder:
	larl	%r2, memsetxc
	ex 	%r3, 0(%r2)
	/* setup pgm interrupt handler */
	larl	%r1, pgm_int_psw
	mvc	GEN_LC_PGM_NEW_PSW(16), 0(%r1)
	/* setup ext interrupt handler */
	larl	%r1, ext_int_psw
	mvc	GEN_LC_EXT_NEW_PSW(16), 0(%r1)
	/* setup mcck interrupt handler */
	larl	%r1, mcck_int_psw
	mvc	GEN_LC_MCCK_NEW_PSW(16), 0(%r1)
	/* setup io interrupt handler */
	larl	%r1, io_int_psw
	mvc	GEN_LC_IO_NEW_PSW(16), 0(%r1)
	/* setup svc interrupt handler */
	larl	%r1, svc_int_psw
	mvc	GEN_LC_SVC_NEW_PSW(16), 0(%r1)
	/* setup cr0, enabling e.g. AFP-register control */
	larl	%r1, initial_cr0
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

memsetxc:
	xc 0(1,%r1),0(%r1)

.section .text
pgm_int:
	CALL_INT_HANDLER handle_pgm_int, GEN_LC_PGM_OLD_PSW

ext_int:
	CALL_INT_HANDLER handle_ext_int, GEN_LC_EXT_OLD_PSW

mcck_int:
	CALL_INT_HANDLER handle_mcck_int, GEN_LC_MCCK_OLD_PSW

io_int:
	CALL_INT_HANDLER handle_io_int, GEN_LC_IO_OLD_PSW

svc_int:
	CALL_INT_HANDLER handle_svc_int, GEN_LC_SVC_OLD_PSW

	.align	8
initial_psw:
	.quad	0x0000000180000000, clear_bss_start
pgm_int_psw:
	.quad	0x0000000180000000, pgm_int
ext_int_psw:
	.quad	0x0000000180000000, ext_int
mcck_int_psw:
	.quad	0x0000000180000000, mcck_int
io_int_psw:
	.quad	0x0000000180000000, io_int
svc_int_psw:
	.quad	0x0000000180000000, svc_int
.globl initial_cr0
initial_cr0:
	/* enable AFP-register control, so FP regs (+BFP instr) can be used */
	.quad	0x0000000000040000
