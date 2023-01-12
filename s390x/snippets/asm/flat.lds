SECTIONS
{
	.lowcore : {
		/*
		 * Initial short psw for disk boot, with 31 bit addressing for
		 * non z/Arch environment compatibility and the instruction
		 * address 0x4000.
		 */
		. = 0;
		 LONG(0x00080000)
		 LONG(0x80004000)
		 /* Restart new PSW for booting via PSW restart. */
		 . = 0x1a0;
		 QUAD(0x0000000180000000)
		 QUAD(0x0000000000004000)
		 /*
		  * Invalid PGM new PSW so we hopefully get a code 8
		  * intercept on a PGM
		  */
		 . = 0x1d0;
		 QUAD(0x0008000000000000)
		 QUAD(0x0000000000000001)
	}
	. = 0x4000;
	/* Start text 0x4000 */
	.text : {
		*(.text)
		*(.text.*)
	}
	. = ALIGN(16);
	etext = .;
	/* End text */
	/* Start data */
	.data : {
		*(.data)
		*(.data.rel*)
	}
	. = ALIGN(16);
	.rodata : { *(.rodata) *(.rodata.*) }
	/* End data */
}
