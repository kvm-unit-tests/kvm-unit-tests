/*
 * Timer tests for the ARM virt machine.
 *
 * Copyright (C) 2017, Alexander Graf <agraf@suse.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#include <libcflat.h>
#include <devicetree.h>
#include <errata.h>
#include <asm/processor.h>
#include <asm/gic.h>
#include <asm/io.h>

#define ARCH_TIMER_CTL_ENABLE  (1 << 0)
#define ARCH_TIMER_CTL_IMASK   (1 << 1)
#define ARCH_TIMER_CTL_ISTATUS (1 << 2)

static void *gic_ispendr;
static bool ptimer_unsupported;

static void ptimer_unsupported_handler(struct pt_regs *regs, unsigned int esr)
{
	ptimer_unsupported = true;
	regs->pc += 4;
}

static u64 read_vtimer_counter(void)
{
	return read_sysreg(cntvct_el0);
}

static u64 read_vtimer_cval(void)
{
	return read_sysreg(cntv_cval_el0);
}

static void write_vtimer_cval(u64 val)
{
	write_sysreg(val, cntv_cval_el0);
}

static u64 read_vtimer_ctl(void)
{
	return read_sysreg(cntv_ctl_el0);
}

static void write_vtimer_ctl(u64 val)
{
	write_sysreg(val, cntv_ctl_el0);
}

static u64 read_ptimer_counter(void)
{
	return read_sysreg(cntpct_el0);
}

static u64 read_ptimer_cval(void)
{
	return read_sysreg(cntp_cval_el0);
}

static void write_ptimer_cval(u64 val)
{
	write_sysreg(val, cntp_cval_el0);
}

static u64 read_ptimer_ctl(void)
{
	return read_sysreg(cntp_ctl_el0);
}

static void write_ptimer_ctl(u64 val)
{
	write_sysreg(val, cntp_ctl_el0);
}

struct timer_info {
	u32 irq;
	u32 irq_flags;
	bool irq_received;
	u64 (*read_counter)(void);
	u64 (*read_cval)(void);
	void (*write_cval)(u64);
	u64 (*read_ctl)(void);
	void (*write_ctl)(u64);
};

static struct timer_info vtimer_info = {
	.irq_received = false,
	.read_counter = read_vtimer_counter,
	.read_cval = read_vtimer_cval,
	.write_cval = write_vtimer_cval,
	.read_ctl = read_vtimer_ctl,
	.write_ctl = write_vtimer_ctl,
};

static struct timer_info ptimer_info = {
	.irq_received = false,
	.read_counter = read_ptimer_counter,
	.read_cval = read_ptimer_cval,
	.write_cval = write_ptimer_cval,
	.read_ctl = read_ptimer_ctl,
	.write_ctl = write_ptimer_ctl,
};

static void set_timer_irq_enabled(struct timer_info *info, bool enabled)
{
	u32 val = 0;

	if (enabled)
		val = 1 << PPI(info->irq);

	switch (gic_version()) {
	case 2:
		writel(val, gicv2_dist_base() + GICD_ISENABLER + 0);
		break;
	case 3:
		writel(val, gicv3_sgi_base() + GICR_ISENABLER0);
		break;
	}
}

static void irq_handler(struct pt_regs *regs)
{
	struct timer_info *info;
	u32 irqstat = gic_read_iar();
	u32 irqnr = gic_iar_irqnr(irqstat);

	if (irqnr != GICC_INT_SPURIOUS)
		gic_write_eoir(irqstat);

	if (irqnr == PPI(vtimer_info.irq)) {
		info = &vtimer_info;
	} else if (irqnr == PPI(ptimer_info.irq)) {
		info = &ptimer_info;
	} else {
		report_info("Unexpected interrupt: %d\n", irqnr);
		return;
	}

	info->write_ctl(ARCH_TIMER_CTL_IMASK | ARCH_TIMER_CTL_ENABLE);
	info->irq_received = true;
}

static bool gic_timer_pending(struct timer_info *info)
{
	return readl(gic_ispendr) & (1 << PPI(info->irq));
}

static bool test_cval_10msec(struct timer_info *info)
{
	u64 time_10ms = read_sysreg(cntfrq_el0) / 100;
	u64 time_1us = time_10ms / 10000;
	u64 before_timer, after_timer;
	s64 difference;

	/* Program timer to fire in 10 ms */
	before_timer = info->read_counter();
	info->write_cval(before_timer + time_10ms);
	info->write_ctl(ARCH_TIMER_CTL_ENABLE);
	isb();

	/* Wait for the timer to fire */
	while (!(info->read_ctl() & ARCH_TIMER_CTL_ISTATUS))
		;

	/* It fired, check how long it took */
	after_timer = info->read_counter();
	difference = after_timer - (before_timer + time_10ms);

	report_info("After timer: 0x%016lx", after_timer);
	report_info("Expected   : 0x%016lx", before_timer + time_10ms);
	report_info("Difference : %ld us", difference / time_1us);

	if (difference < 0) {
		printf("ISTATUS set too early\n");
		return false;
	}
	return difference < time_10ms;
}

static void test_timer(struct timer_info *info)
{
	u64 now = info->read_counter();
	u64 time_10s = read_sysreg(cntfrq_el0) * 10;
	u64 later = now + time_10s;

	/* We don't want the irq handler to fire because that will change the
	 * timer state and we want to test the timer output signal.  We can
	 * still read the pending state even if it's disabled. */
	set_timer_irq_enabled(info, false);

	/* Enable the timer, but schedule it for much later */
	info->write_cval(later);
	info->write_ctl(ARCH_TIMER_CTL_ENABLE);
	isb();
	report("not pending before", !gic_timer_pending(info));

	info->write_cval(now - 1);
	isb();
	report("interrupt signal pending", gic_timer_pending(info));

	/* Disable the timer again and prepare to take interrupts */
	info->write_ctl(0);
	set_timer_irq_enabled(info, true);

	report("latency within 10 ms", test_cval_10msec(info));
	report("interrupt received", info->irq_received);

	/* Disable the timer again */
	info->write_ctl(0);
}

static void test_vtimer(void)
{
	report_prefix_push("vtimer-busy-loop");
	test_timer(&vtimer_info);
	report_prefix_pop();
}

static void test_ptimer(void)
{
	if (ptimer_unsupported)
		return;

	report_prefix_push("ptimer-busy-loop");
	test_timer(&ptimer_info);
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
	assert(fdt32_to_cpu(data[3]) == 1);
	ptimer_info.irq = fdt32_to_cpu(data[4]);
	ptimer_info.irq_flags = fdt32_to_cpu(data[5]);
	assert(fdt32_to_cpu(data[6]) == 1);
	vtimer_info.irq = fdt32_to_cpu(data[7]);
	vtimer_info.irq_flags = fdt32_to_cpu(data[8]);

	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_UNKNOWN, ptimer_unsupported_handler);
	read_sysreg(cntp_ctl_el0);
	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_UNKNOWN, NULL);

	if (ptimer_unsupported && !ERRATA(7b6b46311a85)) {
		report_skip("Skipping ptimer tests. Set ERRATA_7b6b46311a85=y to enable.");
	} else if (ptimer_unsupported) {
		report("ptimer: read CNTP_CTL_EL0", false);
		report_info("ptimer: skipping remaining tests");
	}

	gic_enable_defaults();

	switch (gic_version()) {
	case 2:
		gic_ispendr = gicv2_dist_base() + GICD_ISPENDR;
		break;
	case 3:
		gic_ispendr = gicv3_sgi_base() + GICD_ISPENDR;
		break;
	}

	install_irq_handler(EL1H_IRQ, irq_handler);
	local_irq_enable();
}

static void print_timer_info(void)
{
	printf("CNTFRQ_EL0   : 0x%016lx\n", read_sysreg(cntfrq_el0));

	if (!ptimer_unsupported){
		printf("CNTPCT_EL0   : 0x%016lx\n", read_sysreg(cntpct_el0));
		printf("CNTP_CTL_EL0 : 0x%016lx\n", read_sysreg(cntp_ctl_el0));
		printf("CNTP_CVAL_EL0: 0x%016lx\n", read_sysreg(cntp_cval_el0));
	}

	printf("CNTVCT_EL0   : 0x%016lx\n", read_sysreg(cntvct_el0));
	printf("CNTV_CTL_EL0 : 0x%016lx\n", read_sysreg(cntv_ctl_el0));
	printf("CNTV_CVAL_EL0: 0x%016lx\n", read_sysreg(cntv_cval_el0));
}

int main(int argc, char **argv)
{
	test_init();

	print_timer_info();

	test_vtimer();
	test_ptimer();

	return report_summary();
}
