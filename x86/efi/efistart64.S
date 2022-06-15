/* Startup code and pre-defined data structures */

#include "apic-defs.h"
#include "asm-generic/page.h"
#include "crt0-efi-x86_64.S"


/* Reserve stack in .data */
.data
.align PAGE_SIZE
	. = . + PAGE_SIZE * MAX_TEST_CPUS
.globl stacktop
stacktop:

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
