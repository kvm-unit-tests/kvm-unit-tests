#define SPAPR_KERNEL_LOAD_ADDR 0x400000
.text
.globl start
start:
	b	SPAPR_KERNEL_LOAD_ADDR - 0x100
