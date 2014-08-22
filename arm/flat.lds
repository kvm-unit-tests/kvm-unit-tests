
SECTIONS
{
    .text : { *(.init) *(.text) *(.text.*) }
    . = ALIGN(4K);
    .data : {
        exception_stacks = .;
        . += 4K;
        exception_stacks_end = .;
        *(.data)
    }
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
