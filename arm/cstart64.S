/*
 * Boot entry point and assembler functions for aarch64 tests.
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#define __ASSEMBLY__
#include <auxinfo.h>
#include <asm/asm-offsets.h>
#include <asm/assembler.h>
#include <asm/ptrace.h>
#include <asm/page.h>
#include <asm/pgtable-hwdef.h>
#include <asm/thread_info.h>
#include <asm/sysreg.h>

.macro zero_range, tmp1, tmp2
9998:	cmp	\tmp1, \tmp2
	b.eq	9997f
	stp	xzr, xzr, [\tmp1], #16
	b	9998b
9997:
.endm

.section .init

/*
 * Bootloader params are in x0-x3. See kernel doc
 * Documentation/arm64/booting.txt
 */
.globl start
start:
	/* get our base address */
	adrp	x4, start
	add     x4, x4, :lo12:start

	/*
	 * Update all R_AARCH64_RELATIVE relocations using the table
	 * of Elf64_Rela entries between reloc_start/end. The build
	 * will not emit other relocation types.
	 *
	 * struct Elf64_Rela {
	 * 	uint64_t r_offset;
	 * 	uint64_t r_info;
	 * 	int64_t  r_addend;
	 * }
	 */
	adrp	x5, reloc_start
	add     x5, x5, :lo12:reloc_start
	adrp	x6, reloc_end
	add     x6, x6, :lo12:reloc_end
1:
	cmp	x5, x6
	b.hs	1f
	ldr	x7, [x5]			// r_offset
	ldr	x8, [x5, #16]			// r_addend
	add	x8, x8, x4			// val = base + r_addend
	str	x8, [x4, x7]			// base[r_offset] = val
	add	x5, x5, #24
	b	1b

1:
	/* zero BSS */
	adrp	x4, bss
	add	x4, x4, :lo12:bss
	adrp    x5, ebss
	add     x5, x5, :lo12:ebss
	zero_range x4, x5

	/* zero and set up stack */
	adrp    x5, stacktop
	add     x5, x5, :lo12:stacktop
	sub	x4, x5, #THREAD_SIZE
	zero_range x4, x5

	/* set SCTLR_EL1 to a known value */
	ldr	x4, =INIT_SCTLR_EL1_MMU_OFF
	msr	sctlr_el1, x4
	isb

	mov	x4, #1
	msr	spsel, x4
	adrp    x4, stackptr
	add     sp, x4, :lo12:stackptr

	/* enable FP/ASIMD */
	mov	x4, #(3 << 20)
	msr	cpacr_el1, x4

	/* set up exception handling */
	bl	exceptions_init

	/* complete setup */
	adrp	x1, stacktop
	add	x1, x1, :lo12:stacktop		// x1 is the base of free memory
	bl	setup				// x0 is the addr of the dtb

	/* run the test */
	adrp	x0, __argc
	ldr	w0, [x0, :lo12:__argc]
	adrp	x1, __argv
	add	x1, x1, :lo12:__argv
	adrp	x2, __environ
	add	x2, x2, :lo12:__environ
	bl	main
	bl	exit
	b	halt

.text

/*
 * psci_invoke_hvc / psci_invoke_smc
 *
 * Inputs:
 *   w0 -- function_id
 *   x1 -- arg0
 *   x2 -- arg1
 *   x3 -- arg2
 *
 * Outputs:
 *   x0 -- return code
 */
.globl psci_invoke_hvc
psci_invoke_hvc:
	hvc	#0
	ret

.globl psci_invoke_smc
psci_invoke_smc:
	smc	#0
	ret

get_mmu_off:
	adrp	x0, auxinfo
	ldr	x0, [x0, :lo12:auxinfo + 8]
	and	x0, x0, #AUXINFO_MMU_OFF
	ret

.globl secondary_entry
secondary_entry:
	/* Enable FP/ASIMD */
	mov	x0, #(3 << 20)
	msr	cpacr_el1, x0

	/* set up exception handling */
	bl	exceptions_init

	/* enable the MMU unless requested off */
	bl	get_mmu_off
	cbnz	x0, 1f
	adrp	x0, mmu_idmap
	ldr	x0, [x0, :lo12:mmu_idmap]
	bl	asm_mmu_enable

1:
	/* set the stack */
	adrp	x0, secondary_data
	ldr	x0, [x0, :lo12:secondary_data]
	mov	sp, x0

	/* finish init in C code */
	bl	secondary_cinit

	/* x0 is now the entry function, run it */
	blr	x0
	b	do_idle

.globl halt
halt:
1:	wfi
	b	1b

/*
 * asm_mmu_enable
 *   Inputs:
 *     x0 is the base address of the translation table
 *   Outputs: none
 *
 * Adapted from
 *   arch/arm64/kernel/head.S
 *   arch/arm64/mm/proc.S
 */

/*
 * Memory region attributes for LPAE:
 *
 *   n = AttrIndx[2:0]
 *                      n       MAIR
 *   DEVICE_nGnRnE      000     00000000
 *   DEVICE_nGnRE       001     00000100
 *   DEVICE_GRE         010     00001100
 *   NORMAL_NC          011     01000100
 *   NORMAL             100     11111111
 *   NORMAL_WT          101     10111011
 *   DEVICE_nGRE        110     00001000
 */
#define MAIR(attr, mt) ((attr) << ((mt) * 8))

#if PAGE_SIZE == SZ_64K
#define TCR_TG_FLAGS	TCR_TG0_64K | TCR_TG1_64K
#elif PAGE_SIZE == SZ_16K
#define TCR_TG_FLAGS	TCR_TG0_16K | TCR_TG1_16K
#elif PAGE_SIZE == SZ_4K
#define TCR_TG_FLAGS	TCR_TG0_4K | TCR_TG1_4K
#endif

.globl asm_mmu_enable
asm_mmu_enable:
	tlbi	vmalle1			// invalidate I + D TLBs
	dsb	nsh

	/* TCR */
	ldr	x1, =TCR_TxSZ(VA_BITS) |		\
		     TCR_TG_FLAGS  |			\
		     TCR_IRGN_WBWA | TCR_ORGN_WBWA |	\
		     TCR_SHARED |			\
		     TCR_EPD1
	mrs	x2, id_aa64mmfr0_el1
	bfi	x1, x2, #32, #3
	msr	tcr_el1, x1

	/* MAIR */
	ldr	x1, =MAIR(0x00, MT_DEVICE_nGnRnE) |	\
		     MAIR(0x04, MT_DEVICE_nGnRE) |	\
		     MAIR(0x0c, MT_DEVICE_GRE) |	\
		     MAIR(0x44, MT_NORMAL_NC) |		\
		     MAIR(0xff, MT_NORMAL) |	        \
		     MAIR(0xbb, MT_NORMAL_WT) |         \
		     MAIR(0x08, MT_DEVICE_nGRE)
	msr	mair_el1, x1

	/* TTBR0 */
	msr	ttbr0_el1, x0
	isb

	/* SCTLR */
	mrs	x1, sctlr_el1
	orr	x1, x1, SCTLR_EL1_C
	orr	x1, x1, SCTLR_EL1_I
	orr	x1, x1, SCTLR_EL1_M
	msr	sctlr_el1, x1
	isb

	ret

.globl asm_mmu_disable
asm_mmu_disable:
	mrs	x0, sctlr_el1
	bic	x0, x0, SCTLR_EL1_M
	msr	sctlr_el1, x0
	isb

	/* Clean + invalidate the entire memory */
	adrp	x0, __phys_offset
	ldr	x0, [x0, :lo12:__phys_offset]
	adrp	x1, __phys_end
	ldr	x1, [x1, :lo12:__phys_end]
	sub	x1, x1, x0
	dcache_by_line_op civac, sy, x0, x1, x2, x3

	ret

/*
 * Vectors
 */

exceptions_init:
	adrp	x4, vector_table
	add	x4, x4, :lo12:vector_table
	msr	vbar_el1, x4
	isb
	ret

/*
 * Vector stubs
 * Adapted from arch/arm64/kernel/entry.S
 */
.macro vector_stub, name, vec
\name:
	stp	 x0,  x1, [sp, #-S_FRAME_SIZE]!
	stp	 x2,  x3, [sp,  #16]
	stp	 x4,  x5, [sp,  #32]
	stp	 x6,  x7, [sp,  #48]
	stp	 x8,  x9, [sp,  #64]
	stp	x10, x11, [sp,  #80]
	stp	x12, x13, [sp,  #96]
	stp	x14, x15, [sp, #112]
	stp	x16, x17, [sp, #128]
	stp	x18, x19, [sp, #144]
	stp	x20, x21, [sp, #160]
	stp	x22, x23, [sp, #176]
	stp	x24, x25, [sp, #192]
	stp	x26, x27, [sp, #208]
	stp	x28, x29, [sp, #224]

	str	x30, [sp, #S_LR]

	.if \vec >= 8
	mrs	x1, sp_el0
	.else
	add	x1, sp, #S_FRAME_SIZE
	.endif
	str	x1, [sp, #S_SP]

	mrs	x1, elr_el1
	mrs	x2, spsr_el1
	stp	x1, x2, [sp, #S_PC]

	mov	x0, \vec
	mov	x1, sp
	mrs	x2, esr_el1
	bl	do_handle_exception

	ldp	x1, x2, [sp, #S_PC]
	msr	spsr_el1, x2
	msr	elr_el1, x1

	.if \vec >= 8
	ldr	x1, [sp, #S_SP]
	msr	sp_el0, x1
	.endif

	ldr	x30, [sp, #S_LR]

	ldp	x28, x29, [sp, #224]
	ldp	x26, x27, [sp, #208]
	ldp	x24, x25, [sp, #192]
	ldp	x22, x23, [sp, #176]
	ldp	x20, x21, [sp, #160]
	ldp	x18, x19, [sp, #144]
	ldp	x16, x17, [sp, #128]
	ldp	x14, x15, [sp, #112]
	ldp	x12, x13, [sp,  #96]
	ldp	x10, x11, [sp,  #80]
	ldp	 x8,  x9, [sp,  #64]
	ldp	 x6,  x7, [sp,  #48]
	ldp	 x4,  x5, [sp,  #32]
	ldp	 x2,  x3, [sp,  #16]
	ldp	 x0,  x1, [sp], #S_FRAME_SIZE

	eret
.endm

vector_stub	el1t_sync,     0
vector_stub	el1t_irq,      1
vector_stub	el1t_fiq,      2
vector_stub	el1t_error,    3

vector_stub	el1h_sync,     4
vector_stub	el1h_irq,      5
vector_stub	el1h_fiq,      6
vector_stub	el1h_error,    7

vector_stub	el0_sync_64,   8
vector_stub	el0_irq_64,    9
vector_stub	el0_fiq_64,   10
vector_stub	el0_error_64, 11

vector_stub	el0_sync_32,  12
vector_stub	el0_irq_32,   13
vector_stub	el0_fiq_32,   14
vector_stub	el0_error_32, 15

.section .text.ex

.macro ventry, label
.align 7
	b	\label
.endm

.align 11
vector_table:
	ventry	el1t_sync			// Synchronous EL1t
	ventry	el1t_irq			// IRQ EL1t
	ventry	el1t_fiq			// FIQ EL1t
	ventry	el1t_error			// Error EL1t

	ventry	el1h_sync			// Synchronous EL1h
	ventry	el1h_irq			// IRQ EL1h
	ventry	el1h_fiq			// FIQ EL1h
	ventry	el1h_error			// Error EL1h

	ventry	el0_sync_64			// Synchronous 64-bit EL0
	ventry	el0_irq_64			// IRQ 64-bit EL0
	ventry	el0_fiq_64			// FIQ 64-bit EL0
	ventry	el0_error_64			// Error 64-bit EL0

	ventry	el0_sync_32			// Synchronous 32-bit EL0
	ventry	el0_irq_32			// IRQ 32-bit EL0
	ventry	el0_fiq_32			// FIQ 32-bit EL0
	ventry	el0_error_32			// Error 32-bit EL0
