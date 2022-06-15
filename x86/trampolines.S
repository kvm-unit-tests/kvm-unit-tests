/* Common bootstrapping code to transition from 16-bit to 32-bit code. */

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
