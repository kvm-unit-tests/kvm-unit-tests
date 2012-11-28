#include "libcflat.h"
#include "processor.h"

#define IA32_TSC_ADJUST 0x3b

int main()
{
	u64 t1, t2, t3, t4, t5;
	u64 est_delta_time;
	bool pass = true;

	if (cpuid(7).b & (1 << 1)) { // IA32_TSC_ADJUST Feature is enabled?
		if ( rdmsr(IA32_TSC_ADJUST) != 0x0) {
			printf("failure: IA32_TSC_ADJUST msr was incorrectly"
				" initialized\n");
			pass = false;
		}
		t3 = 100000000000ull;
		t1 = rdtsc();
		wrmsr(IA32_TSC_ADJUST, t3);
		t2 = rdtsc();
		if (rdmsr(IA32_TSC_ADJUST) != t3) {
			printf("failure: IA32_TSC_ADJUST msr read / write"
				" incorrect\n");
			pass = false;
		}
		if (t2 - t1 < t3) {
			printf("failure: TSC did not adjust for IA32_TSC_ADJUST"
				" value\n");
			pass = false;
		}
		t3 = 0x0;
		wrmsr(IA32_TSC_ADJUST, t3);
		if (rdmsr(IA32_TSC_ADJUST) != t3) {
			printf("failure: IA32_TSC_ADJUST msr read / write"
				" incorrect\n");
			pass = false;
		}
		t4 = 100000000000ull;
		t1 = rdtsc();
		wrtsc(t4);
		t2 = rdtsc();
		t5 = rdmsr(IA32_TSC_ADJUST);
		// est of time between reading tsc and writing tsc,
		// (based on IA32_TSC_ADJUST msr value) should be small
		est_delta_time = t4 - t5 - t1;
		if (est_delta_time > 2 * (t2 - t4)) {
			// arbitray 2x latency (wrtsc->rdtsc) threshold
			printf("failure: IA32_TSC_ADJUST msr incorrectly"
				" adjusted on tsc write\n");
			pass = false;
		}
		if (pass) printf("success: IA32_TSC_ADJUST enabled and"
				" working correctly\n");
	}
	else {
		printf("success: IA32_TSC_ADJUST feature not enabled\n");
	}
	return pass?0:1;
}
