#include "spapr.h"

.text
.globl start
start:
	b	SPAPR_KERNEL_LOAD_ADDR - 0x100
