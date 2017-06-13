/*
 * GIC tests
 *
 * GICv2
 *   + test sending/receiving IPIs
 * GICv3
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

#define IPI_SENDER	1
#define IPI_IRQ		1

struct gic {
	struct {
		void (*send_self)(void);
		void (*send_broadcast)(void);
	} ipi;
};

static struct gic *gic;
static int acked[NR_CPUS], spurious[NR_CPUS];
static int bad_sender[NR_CPUS], bad_irq[NR_CPUS];
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

static void stats_reset(void)
{
	int i;

	for (i = 0; i < nr_cpus; ++i) {
		acked[i] = 0;
		bad_sender[i] = -1;
		bad_irq[i] = -1;
	}
	smp_wmb();
}

static void check_acked(cpumask_t *mask)
{
	int missing = 0, extra = 0, unexpected = 0;
	int nr_pass, cpu, i;
	bool bad = false;

	/* Wait up to 5s for all interrupts to be delivered */
	for (i = 0; i < 50; ++i) {
		mdelay(100);
		nr_pass = 0;
		for_each_present_cpu(cpu) {
			smp_rmb();
			nr_pass += cpumask_test_cpu(cpu, mask) ?
				acked[cpu] == 1 : acked[cpu] == 0;

			if (bad_sender[cpu] != -1) {
				printf("cpu%d received IPI from wrong sender %d\n",
					cpu, bad_sender[cpu]);
				bad = true;
			}

			if (bad_irq[cpu] != -1) {
				printf("cpu%d received wrong irq %d\n",
					cpu, bad_irq[cpu]);
				bad = true;
			}
		}
		if (nr_pass == nr_cpus) {
			report("Completed in %d ms", !bad, ++i * 100);
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

static void check_ipi_sender(u32 irqstat)
{
	if (gic_version() == 2) {
		int src = (irqstat >> 10) & 7;

		if (src != IPI_SENDER)
			bad_sender[smp_processor_id()] = src;
	}
}

static void check_irqnr(u32 irqnr)
{
	if (irqnr != IPI_IRQ)
		bad_irq[smp_processor_id()] = irqnr;
}

static void ipi_handler(struct pt_regs *regs __unused)
{
	u32 irqstat = gic_read_iar();
	u32 irqnr = gic_iar_irqnr(irqstat);

	if (irqnr != GICC_INT_SPURIOUS) {
		gic_write_eoir(irqstat);
		smp_rmb(); /* pairs with wmb in stats_reset */
		++acked[smp_processor_id()];
		check_ipi_sender(irqstat);
		check_irqnr(irqnr);
		smp_wmb(); /* pairs with rmb in check_acked */
	} else {
		++spurious[smp_processor_id()];
		smp_wmb();
	}
}

static void gicv2_ipi_send_self(void)
{
	writel(2 << 24 | IPI_IRQ, gicv2_dist_base() + GICD_SGIR);
}

static void gicv2_ipi_send_broadcast(void)
{
	writel(1 << 24 | IPI_IRQ, gicv2_dist_base() + GICD_SGIR);
}

static void gicv3_ipi_send_self(void)
{
	gic_ipi_send_single(IPI_IRQ, smp_processor_id());
}

static void gicv3_ipi_send_broadcast(void)
{
	gicv3_write_sgi1r(1ULL << 40 | IPI_IRQ << 24);
	isb();
}

static void ipi_test_self(void)
{
	cpumask_t mask;

	report_prefix_push("self");
	stats_reset();
	cpumask_clear(&mask);
	cpumask_set_cpu(smp_processor_id(), &mask);
	gic->ipi.send_self();
	check_acked(&mask);
	report_prefix_pop();
}

static void ipi_test_smp(void)
{
	cpumask_t mask;
	int i;

	report_prefix_push("target-list");
	stats_reset();
	cpumask_copy(&mask, &cpu_present_mask);
	for (i = smp_processor_id() & 1; i < nr_cpus; i += 2)
		cpumask_clear_cpu(i, &mask);
	gic_ipi_send_mask(IPI_IRQ, &mask);
	check_acked(&mask);
	report_prefix_pop();

	report_prefix_push("broadcast");
	stats_reset();
	cpumask_copy(&mask, &cpu_present_mask);
	cpumask_clear_cpu(smp_processor_id(), &mask);
	gic->ipi.send_broadcast();
	check_acked(&mask);
	report_prefix_pop();
}

static void ipi_enable(void)
{
	gic_enable_defaults();
#ifdef __arm__
	install_exception_handler(EXCPTN_IRQ, ipi_handler);
#else
	install_irq_handler(EL1H_IRQ, ipi_handler);
#endif
	local_irq_enable();
}

static void ipi_send(void)
{
	ipi_enable();
	wait_on_ready();
	ipi_test_self();
	ipi_test_smp();
	check_spurious();
	exit(report_summary());
}

static void ipi_recv(void)
{
	ipi_enable();
	cpumask_set_cpu(smp_processor_id(), &ready);
	while (1)
		wfi();
}

static void ipi_test(void *data __unused)
{
	if (smp_processor_id() == IPI_SENDER)
		ipi_send();
	else
		ipi_recv();
}

static struct gic gicv2 = {
	.ipi = {
		.send_self = gicv2_ipi_send_self,
		.send_broadcast = gicv2_ipi_send_broadcast,
	},
};

static struct gic gicv3 = {
	.ipi = {
		.send_self = gicv3_ipi_send_self,
		.send_broadcast = gicv3_ipi_send_broadcast,
	},
};

static void ipi_clear_active_handler(struct pt_regs *regs __unused)
{
	u32 irqstat = gic_read_iar();
	u32 irqnr = gic_iar_irqnr(irqstat);

	if (irqnr != GICC_INT_SPURIOUS) {
		void *base;
		u32 val = 1 << IPI_IRQ;

		if (gic_version() == 2)
			base = gicv2_dist_base();
		else
			base = gicv3_redist_base();

		writel(val, base + GICD_ICACTIVER);

		smp_rmb(); /* pairs with wmb in stats_reset */
		++acked[smp_processor_id()];
		check_irqnr(irqnr);
		smp_wmb(); /* pairs with rmb in check_acked */
	} else {
		++spurious[smp_processor_id()];
		smp_wmb();
	}
}

static void run_active_clear_test(void)
{
	report_prefix_push("active");
	gic_enable_defaults();
#ifdef __arm__
	install_exception_handler(EXCPTN_IRQ, ipi_clear_active_handler);
#else
	install_irq_handler(EL1H_IRQ, ipi_clear_active_handler);
#endif
	local_irq_enable();

	ipi_test_self();
	report_prefix_pop();
}

int main(int argc, char **argv)
{
	if (!gic_init()) {
		printf("No supported gic present, skipping tests...\n");
		return report_summary();
	}

	report_prefix_pushf("gicv%d", gic_version());

	switch (gic_version()) {
	case 2:
		gic = &gicv2;
		break;
	case 3:
		gic = &gicv3;
		break;
	}

	if (argc < 2)
		report_abort("no test specified");

	if (strcmp(argv[1], "ipi") == 0) {
		report_prefix_push(argv[1]);
		nr_cpu_check(2);
		on_cpus(ipi_test, NULL);
	} else if (strcmp(argv[1], "active") == 0) {
		run_active_clear_test();
	} else {
		report_abort("Unknown subtest '%s'", argv[1]);
	}

	return report_summary();
}
