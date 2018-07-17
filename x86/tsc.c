#include "libcflat.h"
#include "processor.h"

#define CPUID_80000001_EDX_RDTSCP	    (1 << 27)
static int check_cpuid_80000001_edx(unsigned int bit)
{
	return (cpuid(0x80000001).d & bit) != 0;
}

#define CPUID_7_0_ECX_RDPID		    (1 << 22)
int check_cpuid_7_0_ecx(unsigned int bit)
{
    return (cpuid_indexed(7, 0).c & bit) != 0;
}

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
       report("Test RDTSCP %" PRIu64, ecx == aux, aux);
}

void test_rdpid(u64 aux)
{
       u32 eax;

       wrmsr(MSR_TSC_AUX, aux);
       asm (".byte 0xf3, 0x0f, 0xc7, 0xf8" : "=a" (eax));
       report("Test rdpid %%eax %" PRId64, eax == aux, aux);
}

int main(void)
{
	u64 t1, t2;

	t1 = rdtsc();
	t2 = rdtsc();
	printf("rdtsc latency %u\n", (unsigned)(t2 - t1));

	test_wrtsc(0);
	test_wrtsc(100000000000ull);

	if (check_cpuid_80000001_edx(CPUID_80000001_EDX_RDTSCP)) {
		test_rdtscp(0);
		test_rdtscp(10);
		test_rdtscp(0x100);
	} else
		printf("rdtscp not supported\n");

	if (check_cpuid_7_0_ecx(CPUID_7_0_ECX_RDPID)) {
		test_rdpid(0);
		test_rdpid(10);
		test_rdpid(0x100);
	} else
		printf("rdpid not supported\n");
	return report_summary();
}
