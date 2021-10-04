/* Startup code and pre-defined data structures */

#include "crt0-efi-x86_64.S"

.section .init
.code64
.text

.globl load_idt
load_idt:
	lidtq idt_descr(%rip)
	retq
