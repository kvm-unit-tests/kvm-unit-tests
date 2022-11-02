#include "pmu.h"

struct pmu_caps pmu;

void pmu_init(void)
{
	if (this_cpu_has(X86_FEATURE_PDCM))
		pmu.perf_cap = rdmsr(MSR_IA32_PERF_CAPABILITIES);
}
