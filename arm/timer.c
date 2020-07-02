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
#include <asm/timer.h>
#include <asm/delay.h>
#include <asm/processor.h>
#include <asm/gic.h>
#include <asm/io.h>

static void *gic_isenabler;
static void *gic_icenabler;

static bool ptimer_unsupported;

static void ptimer_unsupported_handler(struct pt_regs *regs, unsigned int esr)
{
	ptimer_unsupported = true;
	regs->pc += 4;
}

static u64 read_vtimer_counter(void)
{
	isb();
	return read_sysreg(cntvct_el0);
}

static u64 read_vtimer_cval(void)
{
	return read_sysreg(cntv_cval_el0);
}

static void write_vtimer_cval(u64 val)
{
	write_sysreg(val, cntv_cval_el0);
	isb();
}

static s32 read_vtimer_tval(void)
{
	return read_sysreg(cntv_tval_el0);
}

static void write_vtimer_tval(s32 val)
{
	write_sysreg(val, cntv_tval_el0);
	isb();
}

static u64 read_vtimer_ctl(void)
{
	return read_sysreg(cntv_ctl_el0);
}

static void write_vtimer_ctl(u64 val)
{
	write_sysreg(val, cntv_ctl_el0);
	isb();
}

static u64 read_ptimer_counter(void)
{
	isb();
	return read_sysreg(cntpct_el0);
}

static u64 read_ptimer_cval(void)
{
	return read_sysreg(cntp_cval_el0);
}

static void write_ptimer_cval(u64 val)
{
	write_sysreg(val, cntp_cval_el0);
	isb();
}

static s32 read_ptimer_tval(void)
{
	return read_sysreg(cntp_tval_el0);
}

static void write_ptimer_tval(s32 val)
{
	write_sysreg(val, cntp_tval_el0);
	isb();
}

static u64 read_ptimer_ctl(void)
{
	return read_sysreg(cntp_ctl_el0);
}

static void write_ptimer_ctl(u64 val)
{
	write_sysreg(val, cntp_ctl_el0);
	isb();
}

struct timer_info {
	u32 irq;
	volatile bool irq_received;
	u64 (*read_counter)(void);
	u64 (*read_cval)(void);
	void (*write_cval)(u64);
	s32 (*read_tval)(void);
	void (*write_tval)(s32);
	u64 (*read_ctl)(void);
	void (*write_ctl)(u64);
};

static struct timer_info vtimer_info = {
	.irq_received = false,
	.read_counter = read_vtimer_counter,
	.read_cval = read_vtimer_cval,
	.write_cval = write_vtimer_cval,
	.read_tval = read_vtimer_tval,
	.write_tval = write_vtimer_tval,
	.read_ctl = read_vtimer_ctl,
	.write_ctl = write_vtimer_ctl,
};

static struct timer_info ptimer_info = {
	.irq_received = false,
	.read_counter = read_ptimer_counter,
	.read_cval = read_ptimer_cval,
	.write_cval = write_ptimer_cval,
	.read_tval = read_ptimer_tval,
	.write_tval = write_ptimer_tval,
	.read_ctl = read_ptimer_ctl,
	.write_ctl = write_ptimer_ctl,
};

static void set_timer_irq_enabled(struct timer_info *info, bool enabled)
{
	u32 val = 1 << PPI(info->irq);

	if (enabled)
		writel(val, gic_isenabler);
	else
		writel(val, gic_icenabler);
}

static void irq_handler(struct pt_regs *regs)
{
	struct timer_info *info;
	u32 irqstat = gic_read_iar();
	u32 irqnr = gic_iar_irqnr(irqstat);

	if (irqnr == PPI(vtimer_info.irq)) {
		info = &vtimer_info;
	} else if (irqnr == PPI(ptimer_info.irq)) {
		info = &ptimer_info;
	} else {
		if (irqnr != GICC_INT_SPURIOUS)
			gic_write_eoir(irqstat);
		report_info("Unexpected interrupt: %d\n", irqnr);
		return;
	}

	info->write_ctl(ARCH_TIMER_CTL_IMASK | ARCH_TIMER_CTL_ENABLE);
	gic_write_eoir(irqstat);

	info->irq_received = true;
}

/* Check that the timer condition is met. */
static bool timer_pending(struct timer_info *info)
{
	return (info->read_ctl() & ARCH_TIMER_CTL_ENABLE) &&
		(info->read_ctl() & ARCH_TIMER_CTL_ISTATUS);
}

static bool gic_timer_check_state(struct timer_info *info,
				  enum gic_irq_state expected_state)
{
	int i;

	/* Wait for up to 1s for the GIC to sample the interrupt. */
	for (i = 0; i < 10; i++) {
		mdelay(100);
		if (gic_irq_state(PPI(info->irq)) == expected_state) {
			mdelay(100);
			if (gic_irq_state(PPI(info->irq)) == expected_state)
				return true;
		}
	}

	return false;
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

	/* Wait for the timer to fire */
	while (!timer_pending(info))
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
	s32 left;

	/* We don't want the irq handler to fire because that will change the
	 * timer state and we want to test the timer output signal.  We can
	 * still read the pending state even if it's disabled. */
	set_timer_irq_enabled(info, false);

	/* Enable the timer, but schedule it for much later */
	info->write_cval(later);
	info->write_ctl(ARCH_TIMER_CTL_ENABLE);
	report(!timer_pending(info) && gic_timer_check_state(info, GIC_IRQ_STATE_INACTIVE),
			"not pending before");

	info->write_cval(now - 1);
	report(timer_pending(info) && gic_timer_check_state(info, GIC_IRQ_STATE_PENDING),
			"interrupt signal pending");

	/* Disable the timer again and prepare to take interrupts */
	info->write_ctl(0);
	info->irq_received = false;
	set_timer_irq_enabled(info, true);
	report(!info->irq_received, "no interrupt when timer is disabled");
	report(!timer_pending(info) && gic_timer_check_state(info, GIC_IRQ_STATE_INACTIVE),
			"interrupt signal no longer pending");

	info->write_cval(now - 1);
	info->write_ctl(ARCH_TIMER_CTL_ENABLE | ARCH_TIMER_CTL_IMASK);
	report(timer_pending(info) && gic_timer_check_state(info, GIC_IRQ_STATE_INACTIVE),
			"interrupt signal not pending");

	report(test_cval_10msec(info), "latency within 10 ms");
	report(info->irq_received, "interrupt received");

	/* Disable the timer again */
	info->write_ctl(0);

	/* Test TVAL and IRQ trigger */
	info->irq_received = false;
	info->write_tval(read_sysreg(cntfrq_el0) / 100);	/* 10 ms */
	local_irq_disable();
	info->write_ctl(ARCH_TIMER_CTL_ENABLE);
	report_info("waiting for interrupt...");
	wfi();
	local_irq_enable();
	left = info->read_tval();
	report(info->irq_received, "interrupt received after TVAL/WFI");
	report(left < 0, "timer has expired");
	report_info("TVAL is %d ticks", left);
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
	assert(TIMER_PTIMER_IRQ != -1 && TIMER_VTIMER_IRQ != -1);
	ptimer_info.irq = TIMER_PTIMER_IRQ;
	vtimer_info.irq = TIMER_VTIMER_IRQ;

	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_UNKNOWN, ptimer_unsupported_handler);
	ptimer_info.read_ctl();
	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_UNKNOWN, NULL);

	if (ptimer_unsupported && !ERRATA(7b6b46311a85)) {
		report_skip("Skipping ptimer tests. Set ERRATA_7b6b46311a85=y to enable.");
	} else if (ptimer_unsupported) {
		report(false, "ptimer: read CNTP_CTL_EL0");
		report_info("ptimer: skipping remaining tests");
	}

	gic_enable_defaults();

	switch (gic_version()) {
	case 2:
		gic_isenabler = gicv2_dist_base() + GICD_ISENABLER;
		gic_icenabler = gicv2_dist_base() + GICD_ICENABLER;
		break;
	case 3:
		gic_isenabler = gicv3_sgi_base() + GICR_ISENABLER0;
		gic_icenabler = gicv3_sgi_base() + GICR_ICENABLER0;
		break;
	}

	install_irq_handler(EL1H_IRQ, irq_handler);
	local_irq_enable();
}

static void print_timer_info(void)
{
	printf("CNTFRQ_EL0   : 0x%016lx\n", read_sysreg(cntfrq_el0));

	if (!ptimer_unsupported) {
		printf("CNTPCT_EL0   : 0x%016lx\n", ptimer_info.read_counter());
		printf("CNTP_CTL_EL0 : 0x%016lx\n", ptimer_info.read_ctl());
		printf("CNTP_CVAL_EL0: 0x%016lx\n", ptimer_info.read_cval());
	}

	printf("CNTVCT_EL0   : 0x%016lx\n", vtimer_info.read_counter());
	printf("CNTV_CTL_EL0 : 0x%016lx\n", vtimer_info.read_ctl());
	printf("CNTV_CVAL_EL0: 0x%016lx\n", vtimer_info.read_cval());
}

int main(int argc, char **argv)
{
	int i;

	test_init();

	print_timer_info();

	if (argc == 1) {
		test_vtimer();
		test_ptimer();
	}

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "vtimer") == 0)
			test_vtimer();
		if (strcmp(argv[i], "ptimer") == 0)
			test_ptimer();
	}

	return report_summary();
}
