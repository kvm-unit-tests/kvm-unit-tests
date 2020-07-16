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
#include <asm/asm-offsets.h>
#include <asm/sigp.h>

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

	.macro SAVE_REGS
	/* save grs 0-15 */
	stmg	%r0, %r15, GEN_LC_SW_INT_GRS
	/* save crs 0-15 */
	stctg	%c0, %c15, GEN_LC_SW_INT_CRS
	/* load a cr0 that has the AFP control bit which enables all FPRs */
	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	/* save fprs 0-15 + fpc */
	la	%r1, GEN_LC_SW_INT_FPRS
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8(%r1)
	.endr
	stfpc	GEN_LC_SW_INT_FPC
	.endm

	.macro RESTORE_REGS
	/* restore fprs 0-15 + fpc */
	la	%r1, GEN_LC_SW_INT_FPRS
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8(%r1)
	.endr
	lfpc	GEN_LC_SW_INT_FPC
	/* restore crs 0-15 */
	lctlg	%c0, %c15, GEN_LC_SW_INT_CRS
	/* restore grs 0-15 */
	lmg	%r0, %r15, GEN_LC_SW_INT_GRS
	.endm

/* Save registers on the stack (r15), so we can have stacked interrupts. */
	.macro SAVE_REGS_STACK
	/* Allocate a stack frame for 15 general registers */
	slgfi   %r15, 15 * 8
	/* Store registers r0 to r14 on the stack */
	stmg    %r0, %r14, 0(%r15)
	/* Allocate a stack frame for 16 floating point registers */
	/* The size of a FP register is the size of an double word */
	slgfi   %r15, 16 * 8
	/* Save fp register on stack: offset to SP is multiple of reg number */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	std	\i, \i * 8(%r15)
	.endr
	/* Save fpc, but keep stack aligned on 64bits */
	slgfi   %r15, 8
	efpc	%r0
	stg	%r0, 0(%r15)
	.endm

/* Restore the register in reverse order */
	.macro RESTORE_REGS_STACK
	/* Restore fpc */
	lfpc	0(%r15)
	algfi	%r15, 8
	/* Restore fp register from stack: SP still where it was left */
	/* and offset to SP is a multiple of reg number */
	.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
	ld	\i, \i * 8(%r15)
	.endr
	/* Now that we're done, rewind the stack pointer by 16 double word */
	algfi   %r15, 16 * 8
	/* Load the registers from stack */
	lmg     %r0, %r14, 0(%r15)
	/* Rewind the stack by 15 double word */
	algfi   %r15, 15 * 8
	.endm

.section .text
/*
 * load_reset calling convention:
 * %r2 subcode (0 or 1)
 */
.globl diag308_load_reset
diag308_load_reset:
	SAVE_REGS
	/* Backup current PSW mask, as we have to restore it on success */
	epsw	%r0, %r1
	st	%r0, GEN_LC_SW_INT_PSW
	st	%r1, GEN_LC_SW_INT_PSW + 4
	/* Load reset psw mask (short psw, 64 bit) */
	lg	%r0, reset_psw
	/* Load the success label address */
	larl    %r1, 0f
	/* Or it to the mask */
	ogr	%r0, %r1
	/* Store it at the reset PSW location (real 0x0) */
	stg	%r0, 0
	/* Do the reset */
	diag    %r0,%r2,0x308
	/* Failure path */
	xgr	%r2, %r2
	br	%r14
	/* Success path */
	/* load a cr0 that has the AFP control bit which enables all FPRs */
0:	larl	%r1, initial_cr0
	lctlg	%c0, %c0, 0(%r1)
	RESTORE_REGS
	lhi	%r2, 1
	larl	%r0, 1f
	stg	%r0, GEN_LC_SW_INT_PSW + 8
	lpswe	GEN_LC_SW_INT_PSW
1:	br	%r14

.globl smp_cpu_setup_state
smp_cpu_setup_state:
	xgr	%r1, %r1
	lmg     %r0, %r15, GEN_LC_SW_INT_GRS
	lctlg   %c0, %c0, GEN_LC_SW_INT_CRS
	/* We should only go once through cpu setup and not for every restart */
	stg	%r14, GEN_LC_RESTART_NEW_PSW + 8
	larl	%r14, 0f
	lpswe	GEN_LC_SW_INT_PSW
	/* If the function returns, just loop here */
0:	j	0

pgm_int:
	SAVE_REGS
	brasl	%r14, handle_pgm_int
	RESTORE_REGS
	lpswe	GEN_LC_PGM_OLD_PSW

ext_int:
	SAVE_REGS
	brasl	%r14, handle_ext_int
	RESTORE_REGS
	lpswe	GEN_LC_EXT_OLD_PSW

mcck_int:
	SAVE_REGS
	brasl	%r14, handle_mcck_int
	RESTORE_REGS
	lpswe	GEN_LC_MCCK_OLD_PSW

io_int:
	SAVE_REGS_STACK
	brasl	%r14, handle_io_int
	RESTORE_REGS_STACK
	lpswe	GEN_LC_IO_OLD_PSW

svc_int:
	SAVE_REGS
	brasl	%r14, handle_svc_int
	RESTORE_REGS
	lpswe	GEN_LC_SVC_OLD_PSW

	.align	8
reset_psw:
	.quad	0x0008000180000000
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
initial_cr0:
	/* enable AFP-register control, so FP regs (+BFP instr) can be used */
	.quad	0x0000000000040000
