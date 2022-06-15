/* Startup code and pre-defined data structures */

#include "apic-defs.h"
#include "asm-generic/page.h"
#include "crt0-efi-x86_64.S"

.data

.align PAGE_SIZE
.globl ptl2
ptl2:
	. = . + 4 * PAGE_SIZE
.align PAGE_SIZE

.globl ptl3
ptl3:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.globl ptl4
ptl4:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.section .init
.code64
.text

.globl load_idt
load_idt:
	lidtq idt_descr(%rip)
	retq

.globl load_gdt_tss
load_gdt_tss:
	/* Load GDT */
	lgdt gdt_descr(%rip)

	/* Load TSS */
	mov %rdi, %rax
	ltr %ax

	/* Update data segments */
	mov $0x10, %ax /* 3rd entry in gdt64: 32/64-bit data segment */
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %fs
	mov %ax, %gs
	mov %ax, %ss

	/*
	 * Update the code segment by putting it on the stack before the return
	 * address, then doing a far return: this will use the new code segment
	 * along with the address.
	 */
	popq %rdi
	pushq $0x08 /* 2nd entry in gdt64: 64-bit code segment */
	pushq %rdi
	lretq

.code16

.globl rm_trampoline
rm_trampoline:

.globl sipi_entry
sipi_entry:
	jmp sipi_entry

.globl sipi_end
sipi_end:

.globl rm_trampoline_end
rm_trampoline_end:
