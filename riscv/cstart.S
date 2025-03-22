/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Boot entry point and assembler functions for riscv.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>


.macro push_fp, ra=ra
	addi	sp, sp, -FP_SIZE
	REG_S	\ra, (FP_SIZE - SZREG)(sp)
	REG_S	fp, (FP_SIZE - 2*SZREG)(sp)
	addi	fp, sp, FP_SIZE
.endm

.macro pop_fp
	REG_L	ra, (FP_SIZE - SZREG)(sp)
	REG_L	fp, (FP_SIZE - 2*SZREG)(sp)
	addi	sp, sp, FP_SIZE
.endm

.macro zero_range, tmp1, tmp2
9998:	beq	\tmp1, \tmp2, 9997f
	REG_S	zero, 0(\tmp1)
	addi	\tmp1, \tmp1, 8
	j	9998b
9997:
.endm

#ifdef CONFIG_EFI
#include "efi/crt0-efi-riscv64.S"
#else
	.section .init

/*
 * The hartid of the current core is in a0
 * The address of the devicetree is in a1
 *
 * See Linux kernel doc Documentation/arch/riscv/boot.rst and
 * Documentation/arch/riscv/boot-image-header.rst
 */
.global start
start:
	j	1f
	.balign	8
	.dword	0x200000			// text offset
	.dword	stacktop - ImageBase		// image size
	.dword	0				// flags
	.word	(0 << 16 | 2 << 0)		// version
	.word	0				// res1
	.dword	0				// res2
	.ascii	"RISCV\0\0\0"			// magic
	.ascii	"RSC\x05"			// magic2
	.word	0				// res3

	/*
	 * Stash the hartid in scratch and shift the dtb address into a0.
	 * thread_info_init() will later promote scratch to point at thread
	 * local storage.
	 */
1:
	csrw	CSR_SSCRATCH, a0
	mv	a0, a1

	/*
	 * Update all R_RISCV_RELATIVE relocations using the table
	 * of Elf32_Rela/Elf64_Rela entries between reloc_start/end.
	 * The build will not emit other relocation types.
	 */
	la	a1, reloc_start
	la	a2, reloc_end
	la	a3, start			// base
1:
	bge	a1, a2, 1f
	REG_L	a4, ELF_RELA_OFFSET(a1)		// r_offset
	REG_L	a5, ELF_RELA_ADDEND(a1)		// r_addend
	add	a4, a3, a4			// addr = base + r_offset
	add	a5, a3, a5			// val = base + r_addend
	REG_S	a5, 0(a4)			// *addr = val
	addi	a1, a1, ELF_RELA_SIZE
	j	1b

1:
	/* zero BSS */
	la	a1, bss
	la	a2, ebss
	zero_range a1, a2

	/* zero and set up stack */
	la	sp, stacktop
	li	a1, -8192
	add	a1, sp, a1
	zero_range a1, sp
	mv	fp, zero			// Ensure fp starts out as zero

	/* set up exception handling */
	la	a1, exception_vectors
	csrw	CSR_STVEC, a1

	/* complete setup */
	la	a1, stacktop			// a1 is the base of free memory
	mv	a2, zero			// clear a2 for xlen=32
	call	setup				// a0 is the addr of the dtb

	/* run the test */
	la	a0, __argc
	lw	a0, 0(a0)
	la	a1, __argv
	la	a2, __environ
	call	main
	call	exit
	j	halt

#endif /* !CONFIG_EFI */
	.text

.balign 4
.global halt
halt:
1:	wfi
	j	1b

/*
 * hartid_to_cpu
 *   a0 is a hartid on entry
 * Returns, in a0, the corresponding cpuid, or -1 if no
 * thread_info struct with 'hartid' is found.
 */
.balign 4
.global hartid_to_cpu
hartid_to_cpu:
	la	t0, cpus
	la	t1, nr_cpus
	lw	t1, 0(t1)
	li	t2, 0
1:	bne	t2, t1, 2f
	li	a0, -1
	ret
2:	REG_L	t3, THREAD_INFO_HARTID(t0)
	bne	a0, t3, 3f
	lw	a0, THREAD_INFO_CPU(t0)
	ret
3:	addi	t0, t0, THREAD_INFO_SIZE
	addi	t2, t2, 1
	j	1b

.balign 4
.global secondary_entry
secondary_entry:
	/*
	 * From the "HSM Hart Start Register State" table of the SBI spec:
	 *	satp		0
	 *	sstatus.SIE	0
	 *	a0		hartid
	 *	a1		opaque parameter
	 *
	 * __smp_boot_secondary() sets the opaque parameter (a1) to the physical
	 * address of the stack and the stack contains the secondary data.
	 */
	csrw	CSR_SSCRATCH, a0
	mv	sp, a1
	mv	fp, zero
	addi	sp, sp, -SECONDARY_DATA_SIZE
	REG_L	a0, SECONDARY_STVEC(sp)
	csrw	CSR_STVEC, a0
	mv	a0, sp
	call	secondary_cinit
	addi	sp, sp, SECONDARY_DATA_SIZE
	jalr	ra, a0
	call	do_idle
	j	.	/* unreachable */

/*
 * Save context to address in a0.
 * For a0, sets PT_A0(a0) to the contents of PT_ORIG_A0(a0).
 * Clobbers a1.
 */
.macro save_context
	REG_S	ra, PT_RA(a0)			// x1
	REG_S	sp, PT_SP(a0)			// x2
	REG_S	gp, PT_GP(a0)			// x3
	REG_S	tp, PT_TP(a0)			// x4
	REG_S	t0, PT_T0(a0)			// x5
	REG_S	t1, PT_T1(a0)			// x6
	REG_S	t2, PT_T2(a0)			// x7
	REG_S	s0, PT_S0(a0)			// x8 / fp
	REG_S	s1, PT_S1(a0)			// x9
	/* a0 */				// x10
	REG_S   a1, PT_A1(a0)			// x11
	REG_S	a2, PT_A2(a0)			// x12
	REG_S	a3, PT_A3(a0)			// x13
	REG_S	a4, PT_A4(a0)			// x14
	REG_S	a5, PT_A5(a0)			// x15
	REG_S	a6, PT_A6(a0)			// x16
	REG_S	a7, PT_A7(a0)			// x17
	REG_S	s2, PT_S2(a0)			// x18
	REG_S	s3, PT_S3(a0)			// x19
	REG_S	s4, PT_S4(a0)			// x20
	REG_S	s5, PT_S5(a0)			// x21
	REG_S	s6, PT_S6(a0)			// x22
	REG_S	s7, PT_S7(a0)			// x23
	REG_S	s8, PT_S8(a0)			// x24
	REG_S	s9, PT_S9(a0)			// x25
	REG_S	s10, PT_S10(a0)			// x26
	REG_S	s11, PT_S11(a0)			// x27
	REG_S	t3, PT_T3(a0)			// x28
	REG_S	t4, PT_T4(a0)			// x29
	REG_S	t5, PT_T5(a0)			// x30
	REG_S	t6, PT_T6(a0)			// x31
	csrr	a1, CSR_SEPC
	REG_S	a1, PT_EPC(a0)
	csrr	a1, CSR_SSTATUS
	REG_S	a1, PT_STATUS(a0)
	csrr	a1, CSR_STVAL
	REG_S	a1, PT_BADADDR(a0)
	csrr	a1, CSR_SCAUSE
	REG_S	a1, PT_CAUSE(a0)
	REG_L	a1, PT_ORIG_A0(a0)
	REG_S	a1, PT_A0(a0)
.endm

/*
 * Restore context from address in a0.
 * Also restores a0.
 */
.macro restore_context
	REG_L	ra, PT_RA(a0)			// x1
	REG_L	sp, PT_SP(a0)			// x2
	REG_L	gp, PT_GP(a0)			// x3
	REG_L	tp, PT_TP(a0)			// x4
	REG_L	t0, PT_T0(a0)			// x5
	REG_L	t1, PT_T1(a0)			// x6
	REG_L	t2, PT_T2(a0)			// x7
	REG_L	s0, PT_S0(a0)			// x8 / fp
	REG_L	s1, PT_S1(a0)			// x9
	/* a0 */				// x10
	/* a1 */				// x11
	REG_L	a2, PT_A2(a0)			// x12
	REG_L	a3, PT_A3(a0)			// x13
	REG_L	a4, PT_A4(a0)			// x14
	REG_L	a5, PT_A5(a0)			// x15
	REG_L	a6, PT_A6(a0)			// x16
	REG_L	a7, PT_A7(a0)			// x17
	REG_L	s2, PT_S2(a0)			// x18
	REG_L	s3, PT_S3(a0)			// x19
	REG_L	s4, PT_S4(a0)			// x20
	REG_L	s5, PT_S5(a0)			// x21
	REG_L	s6, PT_S6(a0)			// x22
	REG_L	s7, PT_S7(a0)			// x23
	REG_L	s8, PT_S8(a0)			// x24
	REG_L	s9, PT_S9(a0)			// x25
	REG_L	s10, PT_S10(a0)			// x26
	REG_L	s11, PT_S11(a0)			// x27
	REG_L	t3, PT_T3(a0)			// x28
	REG_L	t4, PT_T4(a0)			// x29
	REG_L	t5, PT_T5(a0)			// x30
	REG_L	t6, PT_T6(a0)			// x31
	REG_L	a1, PT_EPC(a0)
	csrw	CSR_SEPC, a1
	REG_L	a1, PT_STATUS(a0)
	csrw	CSR_SSTATUS, a1
	REG_L	a1, PT_BADADDR(a0)
	csrw	CSR_STVAL, a1
	REG_L	a1, PT_CAUSE(a0)
	csrw	CSR_SCAUSE, a1
	REG_L	a1, PT_A1(a0)
	REG_L	a0, PT_A0(a0)
.endm

.balign 4
.global exception_vectors
exception_vectors:
	REG_S	a0, (-PT_SIZE - FP_SIZE + PT_ORIG_A0)(sp)
	addi	a0, sp, -PT_SIZE - FP_SIZE
	save_context
	/*
	 * Set a frame pointer "ra" which points to the last instruction.
	 * Add 1 to it, because pretty_print_stacks.py subtracts 1.
	 */
	REG_L	a1, PT_EPC(a0)
	addi	a1, a1, 1
	push_fp	a1
	mv	sp, a0
	call	do_handle_exception
	mv	a0, sp
	restore_context
	sret
