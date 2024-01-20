/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_PGTABLE_H_
#define _ASMRISCV_PGTABLE_H_
#include <linux/const.h>

#if __riscv_xlen == 32
#define SATP_PPN		_AC(0x003FFFFF, UL)
#define SATP_MODE_32		_AC(0x80000000, UL)
#define SATP_MODE_SHIFT		31
#define NR_LEVELS		2
#define PGDIR_BITS		10
#define PGDIR_MASK		_AC(0x3FF, UL)
#define PTE_PPN			_AC(0xFFFFFC00, UL)

#define SATP_MODE_DEFAULT	SATP_MODE_32

#else
#define SATP_PPN		_AC(0x00000FFFFFFFFFFF, UL)
#define SATP_MODE_39		_AC(0x8000000000000000, UL)
#define SATP_MODE_SHIFT		60
#define NR_LEVELS		3
#define PGDIR_BITS		9
#define PGDIR_MASK		_AC(0x1FF, UL)
#define PTE_PPN			_AC(0x3FFFFFFFFFFC00, UL)

#define SATP_MODE_DEFAULT	SATP_MODE_39

#endif

#define PPN_SHIFT		10

#define _PAGE_PRESENT		(1 << 0)
#define _PAGE_READ		(1 << 1)
#define _PAGE_WRITE		(1 << 2)
#define _PAGE_EXEC		(1 << 3)
#define _PAGE_USER		(1 << 4)
#define _PAGE_GLOBAL		(1 << 5)
#define _PAGE_ACCESSED		(1 << 6)
#define _PAGE_DIRTY		(1 << 7)
#define _PAGE_SOFT		(3 << 8)

#endif /* _ASMRISCV_PGTABLE_H_ */
