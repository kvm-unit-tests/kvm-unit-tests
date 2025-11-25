#include "pmu.h"

struct pmu_caps pmu;

/*
 * For Intel Atom CPUs, the PMU events "Instruction Retired" or
 * "Branch Instruction Retired" may be overcounted for some certain
 * instructions, like FAR CALL/JMP, RETF, IRET, VMENTRY/VMEXIT/VMPTRLD
 * and complex SGX/SMX/CSTATE instructions/flows.
 *
 * The detailed information can be found in the errata (section SRF7):
 * https://edc.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/sierra-forest/xeon-6700-series-processor-with-e-cores-specification-update/errata-details/
 *
 * For the Atom platforms before Sierra Forest (including Sierra Forest),
 * Both 2 events "Instruction Retired" and "Branch Instruction Retired" would
 * be overcounted on these certain instructions, but for Clearwater Forest
 * only "Instruction Retired" event is overcounted on these instructions.
 */
static void pmu_detect_intel_overcount_errata(void)
{
	struct cpuid c = cpuid(1);

	if (x86_family(c.a) == 0x6) {
		switch (x86_model(c.a)) {
		case 0xDD: /* Clearwater Forest */
			pmu.errata.instructions_retired_overcount = true;
			break;

		case 0xAF: /* Sierra Forest */
		case 0x4D: /* Avaton, Rangely */
		case 0x5F: /* Denverton */
		case 0x86: /* Jacobsville */
			pmu.errata.instructions_retired_overcount = true;
			pmu.errata.branches_retired_overcount = true;
			break;
		default:
			break;
		}
	}
}

void pmu_init(void)
{
	pmu.is_intel = is_intel();

	if (pmu.is_intel) {
		pmu_detect_intel_overcount_errata();

		pmu.version = this_cpu_property(X86_PROPERTY_PMU_VERSION);

		if (pmu.version > 1) {
			pmu.nr_fixed_counters = this_cpu_property(X86_PROPERTY_PMU_NR_FIXED_COUNTERS);
			pmu.fixed_counter_width = this_cpu_property(X86_PROPERTY_PMU_FIXED_COUNTERS_BIT_WIDTH);
		}

		pmu.nr_gp_counters = this_cpu_property(X86_PROPERTY_PMU_NR_GP_COUNTERS);
		pmu.gp_counter_width = this_cpu_property(X86_PROPERTY_PMU_GP_COUNTERS_BIT_WIDTH);
		pmu.arch_event_mask_length = this_cpu_property(X86_PROPERTY_PMU_EBX_BIT_VECTOR_LENGTH);

		/* CPUID.0xA.EBX bit is '1' if an arch event is NOT available. */
		pmu.arch_event_available = ~this_cpu_property(X86_PROPERTY_PMU_EVENTS_MASK) &
					   (BIT(pmu.arch_event_mask_length) - 1);

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
				pmu.nr_gp_counters = this_cpu_property(X86_PROPERTY_NR_PERFCTR_CORE);
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
		pmu.arch_event_mask_length = 32;
		pmu.arch_event_available = -1u;

		if (this_cpu_has_perf_global_status()) {
			pmu.msr_global_status = MSR_AMD64_PERF_CNTR_GLOBAL_STATUS;
			pmu.msr_global_ctl = MSR_AMD64_PERF_CNTR_GLOBAL_CTL;
			pmu.msr_global_status_clr = MSR_AMD64_PERF_CNTR_GLOBAL_STATUS_CLR;
		}
	}

	pmu_reset_all_counters();
}
