SECTIONS
{
	.text : {
		*(.init)
		. = 0x480;
		ipl_args = .;
		. = 0x600;
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
	.bss : { *(.bss) }
	. = ALIGN(64K);
	edata = .;
	. += 64K;
	. = ALIGN(64K);
	/*
	 * stackptr set with initial stack frame preallocated
	 */
	stackptr = . - 160;
	stacktop = .;
}
