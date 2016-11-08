/*
 * All ripped off from arch/arm64/include/asm/arch_gicv3.h
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#ifndef _ASMARM64_ARCH_GICV3_H_
#define _ASMARM64_ARCH_GICV3_H_

#include <asm/sysreg.h>

#define ICC_PMR_EL1			sys_reg(3, 0, 4, 6, 0)
#define ICC_GRPEN1_EL1			sys_reg(3, 0, 12, 12, 7)

#ifndef __ASSEMBLY__

#include <libcflat.h>
#include <asm/barrier.h>

/*
 * Low-level accessors
 *
 * These system registers are 32 bits, but we make sure that the compiler
 * sets the GP register's most significant bits to 0 with an explicit cast.
 */

static inline void gicv3_write_pmr(u32 val)
{
	asm volatile("msr_s " xstr(ICC_PMR_EL1) ", %0" : : "r" ((u64)val));
}

static inline void gicv3_write_grpen1(u32 val)
{
	asm volatile("msr_s " xstr(ICC_GRPEN1_EL1) ", %0" : : "r" ((u64)val));
	isb();
}

#define gicv3_read_typer(c) readq(c)

#endif /* !__ASSEMBLY__ */
#endif /* _ASMARM64_ARCH_GICV3_H_ */
