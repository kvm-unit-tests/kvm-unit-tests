/*
 * init::start will pass stacktop to setup() as the base of free memory.
 * setup() will then move the FDT and initrd to that base before calling
 * mem_init(). With those movements and this linker script, we'll end up
 * having the following memory layout:
 *
 *    +----------------------+   <-- top of physical memory
 *    |                      |
 *    ~                      ~
 *    |                      |
 *    +----------------------+   <-- top of initrd
 *    |                      |
 *    +----------------------+   <-- top of FDT
 *    |                      |
 *    +----------------------+   <-- top of cpu0's stack
 *    |                      |
 *    +----------------------+   <-- top of text/data/bss sections
 *    |                      |
 *    |                      |
 *    +----------------------+   <-- load address
 *    |                      |
 *    +----------------------+   <-- physical address 0x0
 */

PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    PROVIDE(ImageBase = .);
    PROVIDE(_text = .);
    .text : { *(.init) *(.text) *(.text.*) } :text
    . = ALIGN(4K);
    PROVIDE(_etext = .);

    PROVIDE(reloc_start = .);
    .rela.dyn : { *(.rela.dyn) }
    PROVIDE(reloc_end = .);
    .dynsym   : { *(.dynsym) }
    .dynstr   : { *(.dynstr) }
    .hash     : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }
    .got      : { *(.got) *(.got.plt) }
    .eh_frame : { *(.eh_frame) }

    .rodata   : { *(.rodata*) } :data
    .data     : { *(.data) } :data
    . = ALIGN(16);
    PROVIDE(bss = .);
    .bss      : { *(.bss) }
    . = ALIGN(16);
    PROVIDE(ebss = .);
    . = ALIGN(4K);
    PROVIDE(edata = .);

    /*
     * stack depth is 8K and sp must be 16 byte aligned
     * sp must always be strictly less than the true stacktop
     */
    . += 12K;
    . = ALIGN(4K);
    PROVIDE(stackptr = . - 16);
    PROVIDE(stacktop = .);

    /DISCARD/ : {
        *(.note*)
        *(.interp)
        *(.comment)
        *(.dynamic)
    }
}

ENTRY(start)
