SECTIONS
{
	.lowcore : {
		/*
		 * Initial short psw for disk boot, with 31 bit addressing for
		 * non z/Arch environment compatibility and the instruction
		 * address 0x4000 (cstart.S .init).
		 */
		. = 0;
		 LONG(0x00080000)
		 LONG(0x80004000)
		 /* Restart new PSW for booting via PSW restart. */
		 . = 0x1a0;
		 QUAD(0x0000000180000000)
		 QUAD(0x0000000000004000)
	}
	. = 0x4000;
	.text : {
		*(.init)
		*(.text)
		*(.text.*)
	}
	. = ALIGN(64K);
	etext = .;
	.opd : { *(.opd) }
	. = ALIGN(16);
	.dynamic : {
		dynamic_start = .;
		*(.dynamic)
	}
	.dynsym : {
		dynsym_start = .;
		*(.dynsym)
	}
	.rela.dyn : { *(.rela*) }
	. = ALIGN(16);
	.data : {
		*(.data)
		*(.data.rel*)
	}
	. = ALIGN(16);
	.rodata : { *(.rodata) *(.rodata.*) }
	. = ALIGN(16);
	__bss_start = .;
	.bss : { *(.bss) }
	__bss_end = .;
	. = ALIGN(64K);
	edata = .;
	. += 64K;
	. = ALIGN(64K);
}
