/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Boot entry point and assembler functions for riscv.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <asm/csr.h>

.macro zero_range, tmp1, tmp2
9998:	beq	\tmp1, \tmp2, 9997f
	sd	zero, 0(\tmp1)
	addi	\tmp1, \tmp1, 8
	j	9998b
9997:
.endm

	.section .init

/*
 * The hartid of the current core is in a0
 * The address of the devicetree is in a1
 *
 * See Linux kernel doc Documentation/riscv/boot.rst
 */
.global start
start:
	/*
	 * Stash the hartid in scratch and shift the dtb
	 * address into a0
	 */
	csrw	CSR_SSCRATCH, a0
	mv	a0, a1

	/*
	 * Update all R_RISCV_RELATIVE relocations using the table
	 * of Elf64_Rela entries between reloc_start/end. The build
	 * will not emit other relocation types.
	 *
	 * struct Elf64_Rela {
	 * 	uint64_t r_offset;
	 * 	uint64_t r_info;
	 * 	int64_t  r_addend;
	 * }
	 */
	la	a1, reloc_start
	la	a2, reloc_end
	la	a3, start			// base
1:
	bge	a1, a2, 1f
	ld	a4, 0(a1)			// r_offset
	ld	a5, 16(a1)			// r_addend
	add	a4, a3, a4			// addr = base + r_offset
	add	a5, a3, a5			// val = base + r_addend
	sd	a5, 0(a4)			// *addr = val
	addi	a1, a1, 24
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

	/* set up exception handling */
	//TODO

	/* complete setup */
	la	a1, stacktop			// a1 is the base of free memory
	call	setup				// a0 is the addr of the dtb

	/* run the test */
	la	a0, __argc
	ld	a0, 0(a0)
	la	a1, __argv
	la	a2, __environ
	call	main
	call	exit
	j	halt

	.text

.balign 4
.global halt
halt:
1:	wfi
	j	1b
