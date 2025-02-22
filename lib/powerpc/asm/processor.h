#ifndef _ASMPOWERPC_PROCESSOR_H_
#define _ASMPOWERPC_PROCESSOR_H_

#include <libcflat.h>
#include <asm/ptrace.h>
#include <asm/reg.h>

#ifndef __ASSEMBLER__
void handle_exception(int trap, void (*func)(struct pt_regs *, void *), void *);
void do_handle_exception(struct pt_regs *regs);
#endif /* __ASSEMBLER__ */

extern bool host_is_tcg;
extern bool host_is_kvm;

extern bool cpu_has_hv;
extern bool cpu_has_power_mce;
extern bool cpu_has_siar;
extern bool cpu_has_heai;
extern bool cpu_has_radix;
extern bool cpu_has_prefix;
extern bool cpu_has_sc_lev;
extern bool cpu_has_pause_short;

bool in_usermode(void);

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

static inline void local_irq_enable(void)
{
	unsigned long msr;

	assert(!in_usermode());

	asm volatile(
"		mfmsr	%0		\n \
		ori	%0,%0,%1	\n \
		mtmsrd	%0,1		"
		: "=r"(msr) : "i"(MSR_EE): "memory");
}

static inline void local_irq_disable(void)
{
	unsigned long msr;

	assert(!in_usermode());

	asm volatile(
"		mfmsr	%0		\n \
		andc	%0,%0,%1	\n \
		mtmsrd	%0,1		"
		: "=r"(msr) : "r"(MSR_EE): "memory");
}

/*
 * This returns true on PowerNV / OPAL machines which run in hypervisor
 * mode. False on pseries / PAPR machines that run in guest mode.
 */
static inline bool machine_is_powernv(void)
{
	return cpu_has_hv;
}

/*
 * This returns true on pseries / PAPR / KVM machines which run under a
 * hypervisor or QEMU pseries machine. False for PowerNV / OPAL.
 */
static inline bool machine_is_pseries(void)
{
	return !machine_is_powernv();
}

void enable_mcheck(void);
void disable_mcheck(void);

void enter_usermode(void);
void exit_usermode(void);

#endif /* _ASMPOWERPC_PROCESSOR_H_ */
