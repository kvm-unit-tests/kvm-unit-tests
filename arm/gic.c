/*
 * GIC tests
 *
 * GICv2
 *   + test sending/receiving IPIs
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/setup.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/gic.h>
#include <asm/smp.h>
#include <asm/barrier.h>
#include <asm/io.h>

static int gic_version;
static int acked[NR_CPUS], spurious[NR_CPUS];
static cpumask_t ready;

static void nr_cpu_check(int nr)
{
	if (nr_cpus < nr)
		report_abort("At least %d cpus required", nr);
}

static void wait_on_ready(void)
{
	cpumask_set_cpu(smp_processor_id(), &ready);
	while (!cpumask_full(&ready))
		cpu_relax();
}

static void check_acked(cpumask_t *mask)
{
	int missing = 0, extra = 0, unexpected = 0;
	int nr_pass, cpu, i;

	/* Wait up to 5s for all interrupts to be delivered */
	for (i = 0; i < 50; ++i) {
		mdelay(100);
		nr_pass = 0;
		for_each_present_cpu(cpu) {
			smp_rmb();
			nr_pass += cpumask_test_cpu(cpu, mask) ?
				acked[cpu] == 1 : acked[cpu] == 0;
		}
		if (nr_pass == nr_cpus) {
			report("Completed in %d ms", true, ++i * 100);
			return;
		}
	}

	for_each_present_cpu(cpu) {
		if (cpumask_test_cpu(cpu, mask)) {
			if (!acked[cpu])
				++missing;
			else if (acked[cpu] > 1)
				++extra;
		} else {
			if (acked[cpu])
				++unexpected;
		}
	}

	report("Timed-out (5s). ACKS: missing=%d extra=%d unexpected=%d",
	       false, missing, extra, unexpected);
}

static void check_spurious(void)
{
	int cpu;

	smp_rmb();
	for_each_present_cpu(cpu) {
		if (spurious[cpu])
			report_info("WARN: cpu%d got %d spurious interrupts",
				cpu, spurious[cpu]);
	}
}

static void ipi_handler(struct pt_regs *regs __unused)
{
	u32 irqstat = readl(gicv2_cpu_base() + GICC_IAR);
	u32 irqnr = irqstat & GICC_IAR_INT_ID_MASK;

	if (irqnr != GICC_INT_SPURIOUS) {
		writel(irqstat, gicv2_cpu_base() + GICC_EOIR);
		smp_rmb(); /* pairs with wmb in ipi_test functions */
		++acked[smp_processor_id()];
		smp_wmb(); /* pairs with rmb in check_acked */
	} else {
		++spurious[smp_processor_id()];
		smp_wmb();
	}
}

static void ipi_test_self(void)
{
	cpumask_t mask;

	report_prefix_push("self");
	memset(acked, 0, sizeof(acked));
	smp_wmb();
	cpumask_clear(&mask);
	cpumask_set_cpu(0, &mask);
	writel(2 << 24, gicv2_dist_base() + GICD_SGIR);
	check_acked(&mask);
	report_prefix_pop();
}

static void ipi_test_smp(void)
{
	cpumask_t mask;
	unsigned long tlist;

	report_prefix_push("target-list");
	memset(acked, 0, sizeof(acked));
	smp_wmb();
	tlist = cpumask_bits(&cpu_present_mask)[0] & 0xaa;
	cpumask_bits(&mask)[0] = tlist;
	writel((u8)tlist << 16, gicv2_dist_base() + GICD_SGIR);
	check_acked(&mask);
	report_prefix_pop();

	report_prefix_push("broadcast");
	memset(acked, 0, sizeof(acked));
	smp_wmb();
	cpumask_copy(&mask, &cpu_present_mask);
	cpumask_clear_cpu(0, &mask);
	writel(1 << 24, gicv2_dist_base() + GICD_SGIR);
	check_acked(&mask);
	report_prefix_pop();
}

static void ipi_enable(void)
{
	gicv2_enable_defaults();
#ifdef __arm__
	install_exception_handler(EXCPTN_IRQ, ipi_handler);
#else
	install_irq_handler(EL1H_IRQ, ipi_handler);
#endif
	local_irq_enable();
}

static void ipi_recv(void)
{
	ipi_enable();
	cpumask_set_cpu(smp_processor_id(), &ready);
	while (1)
		wfi();
}

int main(int argc, char **argv)
{
	char pfx[8];
	int cpu;

	gic_version = gic_init();
	if (!gic_version) {
		printf("No supported gic present, skipping tests...\n");
		return report_summary();
	}

	snprintf(pfx, sizeof(pfx), "gicv%d", gic_version);
	report_prefix_push(pfx);

	if (argc < 2)
		report_abort("no test specified");

	if (strcmp(argv[1], "ipi") == 0) {
		report_prefix_push(argv[1]);
		nr_cpu_check(2);

		for_each_present_cpu(cpu) {
			if (cpu == 0)
				continue;
			smp_boot_secondary(cpu, ipi_recv);
		}
		ipi_enable();
		wait_on_ready();
		ipi_test_self();
		ipi_test_smp();
		check_spurious();
		report_prefix_pop();
	} else {
		report_abort("Unknown subtest '%s'", argv[1]);
	}

	return report_summary();
}
