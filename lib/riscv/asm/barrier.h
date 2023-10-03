/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_BARRIER_H_
#define _ASMRISCV_BARRIER_H_

#define RISCV_FENCE(p, s) \
	__asm__ __volatile__ ("fence " #p "," #s : : : "memory")

/* These barriers need to enforce ordering on both devices or memory. */
#define mb()		RISCV_FENCE(iorw,iorw)
#define rmb()		RISCV_FENCE(ir,ir)
#define wmb()		RISCV_FENCE(ow,ow)

/* These barriers do not need to enforce ordering on devices, just memory. */
#define smp_mb()	RISCV_FENCE(rw,rw)
#define smp_rmb()	RISCV_FENCE(r,r)
#define smp_wmb()	RISCV_FENCE(w,w)

#define cpu_relax()	__asm__ __volatile__ ("pause")

#endif /* _ASMRISCV_BARRIER_H_ */
