#include "libcflat.h"
#include "apic.h"
#include "smp.h"

unsigned nipis;

static void ipi_test(void *data)
{
    int n = (long)data;

    printf("ipi called, cpu %d\n", n);
    if (id_map[n] != smp_id())
	printf("but wrong cpu %d\n", smp_id());
    else
        nipis++;
}

int main(void)
{
    int ncpus;
    int i;

    ncpus = cpu_count();
    printf("found %d cpus\n", ncpus);
    for (i = 0; i < ncpus; ++i)
	on_cpu(i, ipi_test, (void *)(long)i);

    report(nipis == ncpus, "IPI to each CPU");
    return report_summary();
}
