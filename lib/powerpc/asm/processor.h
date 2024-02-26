#ifndef _ASMPOWERPC_PROCESSOR_H_
#define _ASMPOWERPC_PROCESSOR_H_

#include <libcflat.h>
#include <asm/ptrace.h>
#include <asm/reg.h>

#ifndef __ASSEMBLY__
void handle_exception(int trap, void (*func)(struct pt_regs *, void *), void *);
void do_handle_exception(struct pt_regs *regs);
#endif /* __ASSEMBLY__ */

static inline uint64_t mfspr(int nr)
{
	uint64_t ret;

	asm volatile("mfspr %0,%1" : "=r"(ret) : "i"(nr) : "memory");

	return ret;
}

static inline void mtspr(int nr, uint64_t val)
{
	asm volatile("mtspr %0,%1" : : "i"(nr), "r"(val) : "memory");
}

static inline uint64_t mfmsr(void)
{
	uint64_t msr;

	asm volatile ("mfmsr %[msr]" : [msr] "=r" (msr) :: "memory");

	return msr;
}

static inline void mtmsr(uint64_t msr)
{
	asm volatile ("mtmsrd %[msr]" :: [msr] "r" (msr) : "memory");
}

#endif /* _ASMPOWERPC_PROCESSOR_H_ */
