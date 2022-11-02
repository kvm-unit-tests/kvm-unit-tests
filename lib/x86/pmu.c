#include "pmu.h"

struct pmu_caps pmu;

void pmu_init(void)
{
	pmu.is_intel = is_intel();

	if (pmu.is_intel) {
		struct cpuid cpuid_10 = cpuid(10);

		pmu.version = cpuid_10.a & 0xff;

		if (pmu.version > 1) {
			pmu.nr_fixed_counters = cpuid_10.d & 0x1f;
			pmu.fixed_counter_width = (cpuid_10.d >> 5) & 0xff;
		}

		if (pmu.version > 1) {
			pmu.nr_fixed_counters = cpuid_10.d & 0x1f;
			pmu.fixed_counter_width = (cpuid_10.d >> 5) & 0xff;
		}

		pmu.nr_gp_counters = (cpuid_10.a >> 8) & 0xff;
		pmu.gp_counter_width = (cpuid_10.a >> 16) & 0xff;
		pmu.gp_counter_mask_length = (cpuid_10.a >> 24) & 0xff;

		/* CPUID.0xA.EBX bit is '1' if a counter is NOT available. */
		pmu.gp_counter_available = ~cpuid_10.b;

		if (this_cpu_has(X86_FEATURE_PDCM))
			pmu.perf_cap = rdmsr(MSR_IA32_PERF_CAPABILITIES);
		pmu.msr_gp_counter_base = MSR_IA32_PERFCTR0;
		pmu.msr_gp_event_select_base = MSR_P6_EVNTSEL0;

		if (this_cpu_has_perf_global_status()) {
			pmu.msr_global_status = MSR_CORE_PERF_GLOBAL_STATUS;
			pmu.msr_global_ctl = MSR_CORE_PERF_GLOBAL_CTRL;
			pmu.msr_global_status_clr = MSR_CORE_PERF_GLOBAL_OVF_CTRL;
		}
	} else {
		if (this_cpu_has(X86_FEATURE_PERFCTR_CORE)) {
			/* Performance Monitoring Version 2 Supported */
			if (this_cpu_has(X86_FEATURE_AMD_PMU_V2)) {
				pmu.version = 2;
				pmu.nr_gp_counters = cpuid(0x80000022).b & 0xf;
			} else {
				pmu.nr_gp_counters = AMD64_NUM_COUNTERS_CORE;
			}
			pmu.msr_gp_counter_base = MSR_F15H_PERF_CTR0;
			pmu.msr_gp_event_select_base = MSR_F15H_PERF_CTL0;
		} else {
			pmu.nr_gp_counters = AMD64_NUM_COUNTERS;
			pmu.msr_gp_counter_base = MSR_K7_PERFCTR0;
			pmu.msr_gp_event_select_base = MSR_K7_EVNTSEL0;
		}
		pmu.gp_counter_width = PMC_DEFAULT_WIDTH;
		pmu.gp_counter_mask_length = pmu.nr_gp_counters;
		pmu.gp_counter_available = (1u << pmu.nr_gp_counters) - 1;

		if (this_cpu_has_perf_global_status()) {
			pmu.msr_global_status = MSR_AMD64_PERF_CNTR_GLOBAL_STATUS;
			pmu.msr_global_ctl = MSR_AMD64_PERF_CNTR_GLOBAL_CTL;
			pmu.msr_global_status_clr = MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR;
		}
	}

	pmu_reset_all_counters();
}
