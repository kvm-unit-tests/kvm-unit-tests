
SECTIONS
{
    .text : { *(.init) *(.text) *(.text.*) }
    . = ALIGN(64K);
    etext = .;
    .data : {
        exception_stacks = .;
        . += 64K;
        exception_stacks_end = .;
        *(.data)
    }
    . = ALIGN(16);
    .rodata : { *(.rodata) }
    . = ALIGN(16);
    .bss : { *(.bss) }
    . = ALIGN(64K);
    edata = .;
    . += 64K;
    . = ALIGN(64K);
    stacktop = .;
}

ENTRY(start)
