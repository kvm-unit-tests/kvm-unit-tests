/*
 * Timer tests for the ARM virt machine.
 *
 * Copyright (C) 2017, Alexander Graf <agraf@suse.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#include <libcflat.h>
#include <devicetree.h>
#include <asm/processor.h>
#include <asm/gic.h>
#include <asm/io.h>

#define CNTV_CTL_ENABLE  (1 << 0)
#define CNTV_CTL_IMASK   (1 << 1)
#define CNTV_CTL_ISTATUS (1 << 2)

static u32 vtimer_irq, vtimer_irq_flags;
static void *gic_ispendr;

static bool gic_vtimer_pending(void)
{
	return readl(gic_ispendr) & (1 << PPI(vtimer_irq));
}

static bool test_cval_10msec(void)
{
	u64 time_10ms = read_sysreg(cntfrq_el0) / 100;
	u64 time_1us = time_10ms / 10000;
	u64 before_timer, after_timer;
	s64 difference;

	/* Program timer to fire in 10 ms */
	before_timer = read_sysreg(cntvct_el0);
	write_sysreg(before_timer + time_10ms, cntv_cval_el0);

	/* Wait for the timer to fire */
	while (!(read_sysreg(cntv_ctl_el0) & CNTV_CTL_ISTATUS))
		;

	/* It fired, check how long it took */
	after_timer = read_sysreg(cntvct_el0);
	difference = after_timer - (before_timer + time_10ms);

	report_info("After timer: 0x%016lx", after_timer);
	report_info("Expected   : 0x%016lx", before_timer + time_10ms);
	report_info("Difference : %ld us", difference / time_1us);

	if (difference < 0) {
		printf("CNTV_CTL_EL0.ISTATUS set too early\n");
		return false;
	}
	return difference < time_10ms;
}

static void test_vtimer(void)
{
	report_prefix_push("vtimer-busy-loop");

	/* Enable the timer */
	write_sysreg(~0, cntv_cval_el0);
	isb();
	write_sysreg(CNTV_CTL_ENABLE, cntv_ctl_el0);

	report("not pending before", !gic_vtimer_pending());
	report("latency within 10 ms", test_cval_10msec());
	report("pending after", gic_vtimer_pending());

	/* Disable the timer again */
	write_sysreg(0, cntv_ctl_el0);

	report_prefix_pop();
}

static void test_init(void)
{
	const struct fdt_property *prop;
	const void *fdt = dt_fdt();
	int node, len;
	u32 *data;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,armv8-timer");
	assert(node >= 0);
	prop = fdt_get_property(fdt, node, "interrupts", &len);
	assert(prop && len == (4 * 3 * sizeof(u32)));
	data = (u32 *)prop->data;
	assert(fdt32_to_cpu(data[6]) == 1);
	vtimer_irq = fdt32_to_cpu(data[7]);
	vtimer_irq_flags = fdt32_to_cpu(data[8]);

	gic_enable_defaults();

	switch (gic_version()) {
	case 2:
		gic_ispendr = gicv2_dist_base() + GICD_ISPENDR;
		break;
	case 3:
		gic_ispendr = gicv3_sgi_base() + GICD_ISPENDR;
		break;
	}
}

int main(void)
{
	printf("CNTFRQ_EL0   : 0x%016lx\n", read_sysreg(cntfrq_el0));
	printf("CNTVCT_EL0   : 0x%016lx\n", read_sysreg(cntvct_el0));
	printf("CNTV_CTL_EL0 : 0x%016lx\n", read_sysreg(cntv_ctl_el0));
	printf("CNTV_CVAL_EL0: 0x%016lx\n", read_sysreg(cntv_cval_el0));

	test_init();
	test_vtimer();

	return report_summary();
}
