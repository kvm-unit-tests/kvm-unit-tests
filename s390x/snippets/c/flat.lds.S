#include <asm/asm-offsets.h>

SECTIONS
{
	.lowcore : {
		/*
		 * Initial short psw for disk boot, with 31 bit addressing for
		 * non z/Arch environment compatibility and the instruction
		 * address 0x4000 (cstart.S .init).
		 */
		. = 0;
		lowcore = .;
		 LONG(0x00080000)
		 LONG(0x80004000)
		 /* Restart new PSW for booting via PSW restart. */
		 . = 0x1a0;
		 QUAD(0x0000000180000000)
		 QUAD(0x0000000000004000)
	}
	. = 0x4000;
	/*
	 * The stack grows down from 0x4000 to 0x2000, we pre-allocoate
	 * a frame via the -STACK_FRAME_SIZE.
	 */
	stackptr = . - STACK_FRAME_SIZE;
	stacktop = .;
	/* Start text 0x4000 */
	.text : {
		*(.init)
		*(.text)
		*(.text.*)
	}
	. = ALIGN(4K);
	etext = .;
	/* End text */
	/* Start data */
	.data : {
		*(.data)
		*(.data.rel*)
	}
	. = ALIGN(16);
	.rodata : { *(.rodata) *(.rodata.*) }
	. = ALIGN(16);
	.bss : { *(.bss) }
	/* End data */
}
