#include "libcflat.h"
#include "processor.h"

static void test_wrtsc(u64 t1)
{
	u64 t2;

	wrtsc(t1);
	t2 = rdtsc();
	printf("rdtsc after wrtsc(%" PRId64 "): %" PRId64 "\n", t1, t2);
}

static void test_rdtscp(u64 aux)
{
       u32 ecx;

       wrmsr(MSR_TSC_AUX, aux);
       rdtscp(&ecx);
       report(ecx == aux, "Test RDTSCP %" PRIu64, aux);
}

static void test_rdpid(u64 aux)
{
       u32 eax;

       wrmsr(MSR_TSC_AUX, aux);
       asm (".byte 0xf3, 0x0f, 0xc7, 0xf8" : "=a" (eax));
       report(eax == aux, "Test rdpid %%eax %" PRId64, aux);
}

int main(void)
{
	u64 t1, t2;

	t1 = rdtsc();
	t2 = rdtsc();
	printf("rdtsc latency %u\n", (unsigned)(t2 - t1));

	test_wrtsc(0);
	test_wrtsc(100000000000ull);

	if (this_cpu_has(X86_FEATURE_RDTSCP)) {
		test_rdtscp(0);
		test_rdtscp(10);
		test_rdtscp(0x100);
	} else
		printf("rdtscp not supported\n");

	if (this_cpu_has(X86_FEATURE_RDPID)) {
		test_rdpid(0);
		test_rdpid(10);
		test_rdpid(0x100);
	} else
		printf("rdpid not supported\n");
	return report_summary();
}
