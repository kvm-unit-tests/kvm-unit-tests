#include "libcflat.h"
#include "smp.h"
#include "atomic.h"
#include "processor.h"
#include "hyperv.h"
#include "vm.h"
#include "alloc_page.h"

#define MAX_CPU 4
#define TICKS_PER_SEC (1000000000 / 100)

struct hv_reference_tsc_page *hv_clock;

/*
 * Scale a 64-bit delta by scaling and multiplying by a 32-bit fraction,
 * yielding a 64-bit result.
 */
static inline u64 scale_delta(u64 delta, u64 mul_frac)
{
	u64 product, unused;

	__asm__ (
		"mulq %3"
		: "=d" (product), "=a" (unused) : "1" (delta), "rm" ((u64)mul_frac) );

	return product;
}

static u64 hvclock_tsc_to_ticks(struct hv_reference_tsc_page *shadow, uint64_t tsc)
{
	u64 delta = tsc;
	return scale_delta(delta, shadow->tsc_scale) + shadow->tsc_offset;
}

/*
 * Reads a consistent set of time-base values from hypervisor,
 * into a shadow data area.
 */
static void hvclock_get_time_values(struct hv_reference_tsc_page *shadow,
				    struct hv_reference_tsc_page *page)
{
	int seq;
	do {
		seq = page->tsc_sequence;
		rmb();		/* fetch version before data */
		*shadow = *page;
		rmb();		/* test version after fetching data */
	} while (shadow->tsc_sequence != seq);
}

static uint64_t hv_clock_read(void)
{
	struct hv_reference_tsc_page shadow;

	hvclock_get_time_values(&shadow, hv_clock);
	return hvclock_tsc_to_ticks(&shadow, rdtsc());
}

bool ok[MAX_CPU];
uint64_t loops[MAX_CPU];

#define iabs(x)   ((x) < 0 ? -(x) : (x))

static void hv_clock_test(void *data)
{
	int i = (long)data;
	uint64_t t_msr_prev = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	uint64_t t_page_prev = hv_clock_read();
	uint64_t end = t_page_prev + TICKS_PER_SEC;
	bool got_drift = false;
	bool got_warp_msr = false;
	bool got_warp_page = false;

	ok[i] = true;
	do {
		uint64_t t_page_1, t_page_2, t_msr;

		t_page_1 = hv_clock_read();
		barrier();
		t_msr = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
		barrier();
		t_page_2 = hv_clock_read();

		if (!got_drift && (t_msr < t_page_1 || t_msr > t_page_2)) {
			printf("drift on CPU %d, MSR value = %ld, acceptable [%ld, %ld]\n", i,
			       t_msr, t_page_1, t_page_2);
			ok[i] = false;
			got_drift = true;
		}

		if (!got_warp_msr && t_msr < t_msr_prev) {
			printf("warp on CPU %d, MSR value = %ld prev MSR value = %ld!\n", i,
			       t_msr, t_msr_prev);
			ok[i] = false;
			got_warp_msr = true;
			break;
		}

		if (!got_warp_page && t_page_1 < t_page_prev) {
			printf("warp on CPU %d, TSC page value = %ld prev TSC page value = %ld!\n", i,
			       t_page_1, t_page_prev);
			ok[i] = false;
			got_warp_page = true;
			break;
		}

		t_page_prev = t_page_1;
		t_msr_prev = t_msr;

	} while(t_page_prev < end);

	barrier();
}

static void check_test(int ncpus)
{
	int i;
	bool pass;

	for (i = ncpus - 1; i >= 0; i--)
		on_cpu_async(i, hv_clock_test, (void *)(long)i);

	while (cpus_active() > 1)
		pause();

	pass = true;
	for (i = ncpus - 1; i >= 0; i--)
		pass &= ok[i];

	report(pass, "TSC reference precision test");
}

static void hv_perf_test(void *data)
{
	int i = (long)data;
	uint64_t t = hv_clock_read();
	uint64_t end = t + 1000000000 / 100;
	uint64_t local_loops = 0;

	do {
		t = hv_clock_read();
		local_loops++;
	} while(t < end);

	loops[i] = local_loops;
}

static void perf_test(int ncpus)
{
	int i;
	uint64_t total_loops;

	for (i = ncpus - 1; i >= 0; i--)
		on_cpu_async(i, hv_perf_test, (void *)(long)i);

	while (cpus_active() > 1)
		pause();

	total_loops = 0;
	for (i = ncpus - 1; i >= 0; i--)
		total_loops += loops[i];
	printf("iterations/sec:  %" PRId64"\n", total_loops / ncpus);
}

int main(int ac, char **av)
{
	int ncpus;
	struct hv_reference_tsc_page shadow;
	uint64_t tsc1, t1, tsc2, t2;
	uint64_t ref1, ref2;

	if (!hv_time_ref_counter_supported()) {
		report_skip("time reference counter is unsupported");
		goto done;
	}

	setup_vm();

	ncpus = cpu_count();
	if (ncpus > MAX_CPU)
		report_abort("number cpus exceeds %d", MAX_CPU);

	hv_clock = alloc_page();
	wrmsr(HV_X64_MSR_REFERENCE_TSC, (u64)(uintptr_t)hv_clock | 1);
	report(rdmsr(HV_X64_MSR_REFERENCE_TSC) == ((u64)(uintptr_t)hv_clock | 1),
	       "MSR value after enabling");

	hvclock_get_time_values(&shadow, hv_clock);
	if (shadow.tsc_sequence == 0 || shadow.tsc_sequence == 0xFFFFFFFF)
		report_abort("Reference TSC page not available\n");

	printf("sequence: %u. scale: %" PRIx64" offset: %" PRId64"\n",
	       shadow.tsc_sequence, shadow.tsc_scale, shadow.tsc_offset);
	ref1 = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	tsc1 = rdtsc();
	t1 = hvclock_tsc_to_ticks(&shadow, tsc1);
	printf("refcnt %" PRId64", TSC %" PRIx64", TSC reference %" PRId64"\n",
	       ref1, tsc1, t1);

	do
		ref2 = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	while (ref2 < ref1 + 2 * TICKS_PER_SEC);

	tsc2 = rdtsc();
	t2 = hvclock_tsc_to_ticks(&shadow, tsc2);
	printf("refcnt %" PRId64" (delta %" PRId64"), TSC %" PRIx64", "
	       "TSC reference %" PRId64" (delta %" PRId64")\n",
	       ref2, ref2 - ref1, tsc2, t2, t2 - t1);

	check_test(ncpus);
	perf_test(ncpus);

	wrmsr(HV_X64_MSR_REFERENCE_TSC, 0LL);
	report(rdmsr(HV_X64_MSR_REFERENCE_TSC) == 0,
	       "MSR value after disabling");

done:
	return report_summary();
}
