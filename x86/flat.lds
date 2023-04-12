PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 4M + SIZEOF_HEADERS;
    stext = .;
    .text : { *(.init) *(.text) *(.text.*) } :text
    etext = .;
    . = ALIGN(4K);
    .data : {
          *(.data)
          exception_table_start = .;
          *(.data.ex)
          exception_table_end = .;
    } :data
    . = ALIGN(16);
    .rodata : { *(.rodata) } :data
    . = ALIGN(16);
    .bss : { *(.bss) }
    . = ALIGN(4K);
    edata = .;
}

ENTRY(start)
