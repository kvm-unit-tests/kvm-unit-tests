#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/desc.h"

#define N 1000000
#define MAX_NUM_LBR_ENTRY	  32
#define DEBUGCTLMSR_LBR	  (1UL <<  0)
#define PMU_CAP_LBR_FMT	  0x3f

#define MSR_LBR_NHM_FROM	0x00000680
#define MSR_LBR_NHM_TO		0x000006c0
#define MSR_LBR_CORE_FROM	0x00000040
#define MSR_LBR_CORE_TO	0x00000060
#define MSR_LBR_TOS		0x000001c9
#define MSR_LBR_SELECT		0x000001c8

volatile int count;
u32 lbr_from, lbr_to;

static noinline int compute_flag(int i)
{
	if (i % 10 < 4)
		return i + 1;
	return 0;
}

static noinline int lbr_test(void)
{
	int i;
	int flag;
	volatile double x = 1212121212, y = 121212;

	for (i = 0; i < 200000000; i++) {
		flag = compute_flag(i);
		count++;
		if (flag)
			x += x / y + y / x;
	}
	return 0;
}

static void init_lbr(void *index)
{
	wrmsr(lbr_from + *(int *) index, 0);
	wrmsr(lbr_to + *(int *)index, 0);
}

static bool test_init_lbr_from_exception(u64 index)
{
	return test_for_exception(GP_VECTOR, init_lbr, &index);
}

int main(int ac, char **av)
{
	u64 perf_cap;
	int max, i;

	setup_vm();

	if (!is_intel()) {
		report_skip("PMU_LBR test is for intel CPU's only");
		return report_summary();
	}

	if (!this_cpu_has_pmu()) {
		report_skip("No pmu is detected!");
		return report_summary();
	}

	if (!this_cpu_has(X86_FEATURE_PDCM)) {
		report_skip("Perfmon/Debug Capabilities MSR isn't supported.");
		return report_summary();
	}

	perf_cap = this_cpu_perf_capabilities();

	if (!(perf_cap & PMU_CAP_LBR_FMT)) {
		report_skip("(Architectural) LBR is not supported.");
		return report_summary();
	}

	printf("PMU version:		 %d\n", pmu_version());
	printf("LBR version:		 %ld\n", perf_cap & PMU_CAP_LBR_FMT);

	/* Look for LBR from and to MSRs */
	lbr_from = MSR_LBR_CORE_FROM;
	lbr_to = MSR_LBR_CORE_TO;
	if (test_init_lbr_from_exception(0)) {
		lbr_from = MSR_LBR_NHM_FROM;
		lbr_to = MSR_LBR_NHM_TO;
	}

	if (test_init_lbr_from_exception(0)) {
		report_skip("LBR on this platform is not supported!");
		return report_summary();
	}

	wrmsr(MSR_LBR_SELECT, 0);
	wrmsr(MSR_LBR_TOS, 0);
	for (max = 0; max < MAX_NUM_LBR_ENTRY; max++) {
		if (test_init_lbr_from_exception(max))
			break;
	}

	report(max > 0, "The number of guest LBR entries is good.");

	/* Do some branch instructions. */
	wrmsr(MSR_IA32_DEBUGCTLMSR, DEBUGCTLMSR_LBR);
	lbr_test();
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0);

	report(rdmsr(MSR_LBR_TOS) != 0, "The guest LBR MSR_LBR_TOS value is good.");
	for (i = 0; i < max; ++i) {
		if (!rdmsr(lbr_to + i) || !rdmsr(lbr_from + i))
			break;
	}
	report(i == max, "The guest LBR FROM_IP/TO_IP values are good.");

	return report_summary();
}
