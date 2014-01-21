
SECTIONS
{
    .text : { *(.init) *(.text) *(.text.*) }
    . = ALIGN(4K);
    .data : { *(.data) }
    . = ALIGN(16);
    .rodata : { *(.rodata) }
    . = ALIGN(16);
    .bss : { *(.bss) }
    . = ALIGN(4K);
    edata = .;
    . += 8K;
    . = ALIGN(4K);
    stacktop = .;
}

ENTRY(start)
