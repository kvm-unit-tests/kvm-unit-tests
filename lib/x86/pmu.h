#ifndef _X86_PMU_H_
#define _X86_PMU_H_

#include "processor.h"
#include "libcflat.h"

#define FIXED_CNT_INDEX 32
#define MAX_NUM_LBR_ENTRY	  32

/* Performance Counter Vector for the LVT PC Register */
#define PMI_VECTOR	32

#define DEBUGCTLMSR_LBR	  (1UL <<  0)

#define PMU_CAP_LBR_FMT	  0x3f
#define PMU_CAP_FW_WRITES	(1ULL << 13)
#define PMU_CAP_PEBS_BASELINE	(1ULL << 14)
#define PERF_CAP_PEBS_FORMAT           0xf00

#define EVNSEL_EVENT_SHIFT	0
#define EVNTSEL_UMASK_SHIFT	8
#define EVNTSEL_USR_SHIFT	16
#define EVNTSEL_OS_SHIFT	17
#define EVNTSEL_EDGE_SHIFT	18
#define EVNTSEL_PC_SHIFT	19
#define EVNTSEL_INT_SHIFT	20
#define EVNTSEL_EN_SHIF		22
#define EVNTSEL_INV_SHIF	23
#define EVNTSEL_CMASK_SHIFT	24

#define EVNTSEL_EN	(1 << EVNTSEL_EN_SHIF)
#define EVNTSEL_USR	(1 << EVNTSEL_USR_SHIFT)
#define EVNTSEL_OS	(1 << EVNTSEL_OS_SHIFT)
#define EVNTSEL_PC	(1 << EVNTSEL_PC_SHIFT)
#define EVNTSEL_INT	(1 << EVNTSEL_INT_SHIFT)
#define EVNTSEL_INV	(1 << EVNTSEL_INV_SHIF)

#define GLOBAL_STATUS_BUFFER_OVF_BIT		62
#define GLOBAL_STATUS_BUFFER_OVF	BIT_ULL(GLOBAL_STATUS_BUFFER_OVF_BIT)

#define PEBS_DATACFG_MEMINFO	BIT_ULL(0)
#define PEBS_DATACFG_GP	BIT_ULL(1)
#define PEBS_DATACFG_XMMS	BIT_ULL(2)
#define PEBS_DATACFG_LBRS	BIT_ULL(3)

#define ICL_EVENTSEL_ADAPTIVE				(1ULL << 34)
#define PEBS_DATACFG_LBR_SHIFT	24
#define MAX_NUM_LBR_ENTRY	32

struct pmu_caps {
	u8 version;
	u8 nr_fixed_counters;
	u8 fixed_counter_width;
	u8 nr_gp_counters;
	u8 gp_counter_width;
	u8 gp_counter_mask_length;
	u32 gp_counter_available;
	u32 msr_gp_counter_base;
	u32 msr_gp_event_select_base;

	u32 msr_global_status;
	u32 msr_global_ctl;
	u32 msr_global_status_clr;

	u64 perf_cap;
};

extern struct pmu_caps pmu;

void pmu_init(void);

static inline u32 MSR_GP_COUNTERx(unsigned int i)
{
	return pmu.msr_gp_counter_base + i;
}

static inline u32 MSR_GP_EVENT_SELECTx(unsigned int i)
{
	return pmu.msr_gp_event_select_base + i;
}

static inline bool this_cpu_has_pmu(void)
{
	return !!pmu.version;
}

static inline bool this_cpu_has_perf_global_ctrl(void)
{
	return pmu.version > 1;
}

static inline bool this_cpu_has_perf_global_status(void)
{
	return pmu.version > 1;
}

static inline bool pmu_gp_counter_is_available(int i)
{
	return pmu.gp_counter_available & BIT(i);
}

static inline u64 pmu_lbr_version(void)
{
	return pmu.perf_cap & PMU_CAP_LBR_FMT;
}

static inline bool pmu_has_full_writes(void)
{
	return pmu.perf_cap & PMU_CAP_FW_WRITES;
}

static inline void pmu_activate_full_writes(void)
{
	pmu.msr_gp_counter_base = MSR_IA32_PMC0;
}

static inline bool pmu_use_full_writes(void)
{
	return pmu.msr_gp_counter_base == MSR_IA32_PMC0;
}

static inline u32 MSR_PERF_FIXED_CTRx(unsigned int i)
{
	return MSR_CORE_PERF_FIXED_CTR0 + i;
}

static inline void pmu_reset_all_gp_counters(void)
{
	unsigned int idx;

	for (idx = 0; idx < pmu.nr_gp_counters; idx++) {
		wrmsr(MSR_GP_EVENT_SELECTx(idx), 0);
		wrmsr(MSR_GP_COUNTERx(idx), 0);
	}
}

static inline void pmu_reset_all_fixed_counters(void)
{
	unsigned int idx;

	if (!pmu.nr_fixed_counters)
		return;

	wrmsr(MSR_CORE_PERF_FIXED_CTR_CTRL, 0);
	for (idx = 0; idx < pmu.nr_fixed_counters; idx++)
		wrmsr(MSR_PERF_FIXED_CTRx(idx), 0);
}

static inline void pmu_reset_all_counters(void)
{
	pmu_reset_all_gp_counters();
	pmu_reset_all_fixed_counters();
}

static inline void pmu_clear_global_status(void)
{
	wrmsr(pmu.msr_global_status_clr, rdmsr(pmu.msr_global_status));
}

static inline bool pmu_has_pebs(void)
{
	return pmu.version > 1;
}

static inline u8 pmu_pebs_format(void)
{
	return (pmu.perf_cap & PERF_CAP_PEBS_FORMAT ) >> 8;
}

static inline bool pmu_has_pebs_baseline(void)
{
	return pmu.perf_cap & PMU_CAP_PEBS_BASELINE;
}

#endif /* _X86_PMU_H_ */
