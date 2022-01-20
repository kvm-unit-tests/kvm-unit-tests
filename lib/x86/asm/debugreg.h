/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASMX86_DEBUGREG_H_
#define _ASMX86_DEBUGREG_H_

#include <bitops.h>

/*
 * DR6_ACTIVE_LOW combines fixed-1 and active-low bits (e.g. RTM), and is also
 * the init/reset value for DR6.
 */
#define DR6_ACTIVE_LOW	0xffff0ff0
#define DR6_VOLATILE	0x0001e80f
#define DR6_FIXED_1	(DR6_ACTIVE_LOW & ~DR6_VOLATILE)

#define DR6_TRAP0	BIT(0)		/* DR0 matched */
#define DR6_TRAP1	BIT(1)		/* DR1 matched */
#define DR6_TRAP2	BIT(2)		/* DR2 matched */
#define DR6_TRAP3	BIT(3)		/* DR3 matched */
#define DR6_TRAP_BITS	(DR6_TRAP0|DR6_TRAP1|DR6_TRAP2|DR6_TRAP3)

#define DR6_BUS_LOCK	BIT(11)		/* Bus lock	    0x800 */
#define DR6_BD		BIT(13)		/* General Detect  0x2000 */
#define DR6_BS		BIT(14)		/* Single-Step	   0x4000 */
#define DR6_BT		BIT(15)		/* Task Switch	   0x8000 */
#define DR6_RTM		BIT(16)		/* RTM / TSX	  0x10000 */

#define DR7_FIXED_1	0x00000400	/* init/reset value, too */
#define DR7_VOLATILE	0xffff2bff
#define DR7_BP_EN_MASK	0x000000ff
#define DR7_LE		BIT(8)		/* Local Exact	    0x100 */
#define DR7_GE		BIT(9)		/* Global Exact     0x200 */
#define DR7_RTM		BIT(11)		/* RTM / TSX	    0x800 */
#define DR7_GD		BIT(13)		/* General Detect  0x2000 */

/*
 * Enable bits for DR0-D3.  Bits 0, 2, 4, and 6 are local enable bits (cleared
 * by the CPU on task switch), bits 1, 3, 5, and 7 are global enable bits
 * (never cleared by the CPU).
 */
#define DR7_LOCAL_ENABLE_DRx(x)		(BIT(0) << (x))
#define DR7_GLOBAL_ENABLE_DRx(x)	(BIT(1) << (x))
#define DR7_ENABLE_DRx(x) \
	(DR7_LOCAL_ENABLE_DRx(x) | DR7_GLOBAL_ENABLE_DRx(x))

#define DR7_GLOBAL_ENABLE_DR0	DR7_GLOBAL_ENABLE_DRx(0)
#define DR7_GLOBAL_ENABLE_DR1	DR7_GLOBAL_ENABLE_DRx(1)
#define DR7_GLOBAL_ENABLE_DR2	DR7_GLOBAL_ENABLE_DRx(2)
#define DR7_GLOBAL_ENABLE_DR3	DR7_GLOBAL_ENABLE_DRx(3)

/* Condition/type of the breakpoint for DR0-3. */
#define DR7_RW_TYPE_DRx(x, rw)	((rw) << (((x) * 4) + 16))
#define DR7_EXECUTE_DRx(x)	DR7_RW_TYPE_DRx(x, 0)
#define DR7_WRITE_DRx(x)	DR7_RW_TYPE_DRx(x, 1)
#define DR7_PORT_IO_DRx(x)	DR7_RW_TYPE_DRx(x, 2)
#define DR7_DATA_IO_DRx(x)	DR7_RW_TYPE_DRx(x, 3)	/* Read or Write */

/* Length of the breakpoint for DR0-3. */
#define DR7_LEN_DRx(x, enc)	((enc) << (((x) * 4) + 18))
#define DR7_LEN_1_DRx(x)	DR7_LEN_DRx(x, 0)
#define DR7_LEN_2_DRx(x)	DR7_LEN_DRx(x, 1)
#define DR7_LEN_4_DRx(x)	DR7_LEN_DRx(x, 3)
#define DR7_LEN_8_DRx(x)	DR7_LEN_DRx(x, 2) /* Out of sequence, undefined for 32-bit CPUs. */

#endif /* _ASMX86_DEBUGREG_H_ */
