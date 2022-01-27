#include "libcflat.h"
#include "processor.h"

int main(void)
{
	u64 t1, t2, t3, t4, t5;

	if (!this_cpu_has(X86_FEATURE_TSC_ADJUST)) {
		report_skip("MSR_IA32_TSC_ADJUST feature not enabled");
		return report_summary();
	}

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
	report(t1 <= t4 - t5, "Internal TSC advances across write to IA32_TSC");
	report(t2 >= t4, "IA32_TSC advances after write to IA32_TSC");

	return report_summary();
}
