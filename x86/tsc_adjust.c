#include "libcflat.h"
#include "processor.h"

int main(void)
{
	u64 t1, t2, t3, t4, t5;
	u64 est_delta_time;

	if (this_cpu_has(X86_FEATURE_TSC_ADJUST)) { // MSR_IA32_TSC_ADJUST Feature is enabled?
		report(rdmsr(MSR_IA32_TSC_ADJUST) == 0x0,
		       "MSR_IA32_TSC_ADJUST msr initialization");
		t3 = 100000000000ull;
		t1 = rdtsc();
		wrmsr(MSR_IA32_TSC_ADJUST, t3);
		t2 = rdtsc();
		report(rdmsr(MSR_IA32_TSC_ADJUST) == t3,
		       "MSR_IA32_TSC_ADJUST msr read / write");
		report((t2 - t1) >= t3,
		       "TSC adjustment for MSR_IA32_TSC_ADJUST value");
		t3 = 0x0;
		wrmsr(MSR_IA32_TSC_ADJUST, t3);
		report(rdmsr(MSR_IA32_TSC_ADJUST) == t3,
		       "MSR_IA32_TSC_ADJUST msr read / write");
		t4 = 100000000000ull;
		t1 = rdtsc();
		wrtsc(t4);
		t2 = rdtsc();
		t5 = rdmsr(MSR_IA32_TSC_ADJUST);
		// est of time between reading tsc and writing tsc,
		// (based on MSR_IA32_TSC_ADJUST msr value) should be small
		est_delta_time = t4 - t5 - t1;
		// arbitray 2x latency (wrtsc->rdtsc) threshold
		report(est_delta_time <= (2 * (t2 - t4)),
		       "MSR_IA32_TSC_ADJUST msr adjustment on tsc write");
	}
	else {
		report(true, "MSR_IA32_TSC_ADJUST feature not enabled");
	}
	return report_summary();
}
