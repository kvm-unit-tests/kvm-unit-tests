/*
 * Common bootstrapping code to transition from 16-bit to 32-bit code, and to
 * transition from 32-bit to 64-bit code (x86-64 only)
 */

 /* EFI provides it's own SIPI sequence to handle relocation. */
#ifndef CONFIG_EFI
.code16
.globl rm_trampoline
rm_trampoline:

/* Store SIPI vector code at the beginning of trampoline. */
sipi_entry:
	mov %cr0, %eax
	or $1, %eax
	mov %eax, %cr0
	lgdtl ap_rm_gdt_descr - sipi_entry
	ljmpl $8, $ap_start32
sipi_end:

.globl ap_rm_gdt_descr
ap_rm_gdt_descr:
#ifdef __i386__
	.word 0
	.long 0
#else
	.word gdt32_end - gdt32 - 1
	.long gdt32
#endif

.globl rm_trampoline_end
rm_trampoline_end:
#endif

/* The 32-bit => 64-bit trampoline is x86-64 only. */
#ifdef __x86_64__
.code32

MSR_GS_BASE = 0xc0000101

.macro setup_percpu_area
	lea -4096(%esp), %eax
	mov $0, %edx
	mov $MSR_GS_BASE, %ecx
	wrmsr
.endm

.macro setup_segments
	mov $MSR_GS_BASE, %ecx
	rdmsr

	mov $0x10, %bx
	mov %bx, %ds
	mov %bx, %es
	mov %bx, %fs
	mov %bx, %gs
	mov %bx, %ss

	/* restore MSR_GS_BASE */
	wrmsr
.endm

prepare_64:
	lgdt gdt_descr
	setup_segments

	xor %eax, %eax
	mov %eax, %cr4

enter_long_mode:
	mov %cr4, %eax
	bts $5, %eax  // pae
	mov %eax, %cr4

	mov pt_root, %eax
	mov %eax, %cr3

efer = 0xc0000080
	mov $efer, %ecx
	rdmsr
	bts $8, %eax
	wrmsr

	mov %cr0, %eax
	bts $0, %eax
	bts $31, %eax
	mov %eax, %cr0
	ret

ap_start32:
	setup_segments
	mov $-4096, %esp
	lock xaddl %esp, smp_stacktop
	setup_percpu_area
	call prepare_64
	ljmpl $8, $ap_start64
#endif
