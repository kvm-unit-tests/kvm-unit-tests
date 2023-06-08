#ifndef _ASMPOWERPC_PROCESSOR_H_
#define _ASMPOWERPC_PROCESSOR_H_

#include <libcflat.h>
#include <asm/ptrace.h>

#ifndef __ASSEMBLY__
void handle_exception(int trap, void (*func)(struct pt_regs *, void *), void *);
void do_handle_exception(struct pt_regs *regs);
#endif /* __ASSEMBLY__ */

#define SPR_TB		0x10c
#define SPR_SPRG0	0x110
#define SPR_SPRG1	0x111
#define SPR_SPRG2	0x112
#define SPR_SPRG3	0x113

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

static inline uint64_t get_tb(void)
{
	return mfspr(SPR_TB);
}

extern void delay(uint64_t cycles);
extern void udelay(uint64_t us);
extern void sleep_tb(uint64_t cycles);
extern void usleep(uint64_t us);

static inline void mdelay(uint64_t ms)
{
	while (ms--)
		udelay(1000);
}

static inline void msleep(uint64_t ms)
{
	usleep(ms * 1000);
}

#endif /* _ASMPOWERPC_PROCESSOR_H_ */
