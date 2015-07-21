
SECTIONS
{
    .text : { *(.init) *(.text) *(.text.*) }
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
    . = ALIGN(256);
    /*
     * tocptr is tocbase + 32K, allowing toc offsets to be +-32K
     */
    tocptr = . + 32K;
    .got : { *(.toc) *(.got) }
    . = ALIGN(64K);
    edata = .;
    . += 64K;
    . = ALIGN(64K);
    /*
     * stackptr set with initial stack frame (64 bytes) preallocated
     */
    stackptr = . - 64;
    stacktop = .;
}

ENTRY(start)
