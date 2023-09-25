/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Boot entry point and assembler functions for riscv.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <asm/asm-offsets.h>
#include <asm/csr.h>

#if __riscv_xlen == 64
#define __REG_SEL(a, b) a
#elif __riscv_xlen == 32
#define __REG_SEL(a, b) b
#else
#error "Unexpected __riscv_xlen"
#endif

#define REG_L	__REG_SEL(ld, lw)
#define REG_S	__REG_SEL(sd, sw)

.macro zero_range, tmp1, tmp2
9998:	beq	\tmp1, \tmp2, 9997f
	REG_S	zero, 0(\tmp1)
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

	/* set up exception handling */
	//TODO

	/* complete setup */
	la	a1, stacktop			// a1 is the base of free memory
	mv	a2, zero			// clear a2 for xlen=32
	call	setup				// a0 is the addr of the dtb

	/* run the test */
	la	a0, __argc
	REG_L	a0, 0(a0)
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
