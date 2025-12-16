#include "libcflat.h"
#include "smp.h"
#include "apic.h"
#include "asm/barrier.h"
#include "x86/atomic.h"
#include "vmalloc.h"
#include "alloc.h"

#define HPET_ADDR         0xFED00000L
#define HPET_COUNTER_ADDR ((uint8_t *)HPET_ADDR + 0xF0UL)
#define HPET_CONFIG_ADDR  ((uint8_t *)HPET_ADDR + 0x10UL)
#define HPET_ENABLE_BIT   0x01UL
#define HPET_CLK_PERIOD   10

#define TEST_CYCLES 100000

static atomic_t fail;
static uint64_t latency[MAX_TEST_CPUS];

static void hpet_reader(void *data)
{
	long i;
	uint64_t old_counter = 0, new_counter;
	long id = (long)data;

	latency[id] = *(uint64_t *)HPET_COUNTER_ADDR;
	for (i = 0; i < TEST_CYCLES; ++i) {
		new_counter = *(uint64_t *)HPET_COUNTER_ADDR;
		if (new_counter < old_counter)
			atomic_inc(&fail);
		old_counter = new_counter;
	}
	/* claculate job latency in ns */
	latency[id] = (*(uint64_t *)HPET_COUNTER_ADDR - latency[id])
		* HPET_CLK_PERIOD / TEST_CYCLES;
}

static void hpet_writer(void *data)
{
	int i;

	for (i = 0; i < TEST_CYCLES; ++i)
		if (i % 2)
			*(uint64_t *)HPET_CONFIG_ADDR |= HPET_ENABLE_BIT;
		else
			*(uint64_t *)HPET_CONFIG_ADDR &= ~HPET_ENABLE_BIT;
}

int main(void)
{
	unsigned long cpu, time_ns, lat = 0;
	uint64_t start, end;
	int ncpus = cpu_count();

	do {
		printf("* starting concurrent read bench on %d cpus\n", ncpus);
		*(uint64_t *)HPET_CONFIG_ADDR |= HPET_ENABLE_BIT;
		start = *(uint64_t *)HPET_COUNTER_ADDR;

		for (cpu = cpu_count() - 1; cpu > 0; --cpu)
			on_cpu_async(cpu, hpet_reader, (void *)cpu);
		while (cpus_active() > 1)
			pause();

		end = (*(uint64_t *)HPET_COUNTER_ADDR);
		time_ns = (end - start) * HPET_CLK_PERIOD;

		for (cpu = 1; cpu < ncpus; cpu++)
			if (latency[cpu])
				lat += latency[cpu];
			else
				report_fail("cpu %lu reported invalid latency (0)\n", cpu);
		lat = lat / ncpus;

		report(time_ns && !atomic_read(&fail),
			"read test took %lu ms, avg read: %lu ns\n", time_ns/1000000,  lat);
	} while (0);

	do {
		printf("* starting enable/disable with concurrent readers torture\n");
		if (ncpus > 2) {
			for (cpu = 2; cpu < ncpus; cpu++)
				on_cpu_async(cpu, hpet_reader, (void *)TEST_CYCLES);

			on_cpu(1, hpet_writer, (void *)TEST_CYCLES);
			report(!atomic_read(&fail), "torture test, fails: %u\n",
				atomic_read(&fail));
		} else
			printf("SKIP: torture test: '-smp X' should be greater than 2\n");
	} while (0);

	return report_summary();
}
