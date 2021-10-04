/* Startup code and pre-defined data structures */

#include "apic-defs.h"
#include "asm-generic/page.h"
#include "crt0-efi-x86_64.S"

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
