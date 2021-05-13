/*
 * Measure the cost of micro level operations.
 *
 * This test provides support for quantifying the cost of micro level
 * operations. To improve precision in the measurements, one should
 * consider pinning each VCPU to a specific physical CPU (PCPU) and to
 * ensure no other task could run on that PCPU to skew the results.
 * This can be achieved by enabling QMP server in the QEMU command in
 * unittest.cfg for micro-bench, allowing a client program to get the
 * thread_id for each VCPU thread from the QMP server. Based on that
 * information, the client program can then pin the corresponding VCPUs to
 * dedicated PCPUs and isolate interrupts and tasks from those PCPUs.
 *
 * Copyright Columbia University
 * Author: Shih-Wei Li <shihwei@cs.columbia.edu>
 * Author: Christoffer Dall <cdall@cs.columbia.edu>
 * Author: Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/gic.h>
#include <asm/gic-v3-its.h>
#include <asm/timer.h>

#define NS_5_SECONDS (5 * 1000 * 1000 * 1000UL)

static u32 cntfrq;

static volatile bool irq_ready, irq_received;
static int nr_ipi_received;

static void *vgic_dist_base;
static void (*write_eoir)(u32 irqstat);

static void gic_irq_handler(struct pt_regs *regs)
{
	u32 irqstat = gic_read_iar();
	irq_ready = false;
	irq_received = true;
	gic_write_eoir(irqstat);

	if (irqstat == PPI(TIMER_VTIMER_IRQ)) {
		write_sysreg((ARCH_TIMER_CTL_IMASK | ARCH_TIMER_CTL_ENABLE),
			     cntv_ctl_el0);
		isb();
	}
	irq_ready = true;
}

static void gic_secondary_entry(void *data)
{
	install_irq_handler(EL1H_IRQ, gic_irq_handler);
	gic_enable_defaults();
	local_irq_enable();
	irq_ready = true;
	while (true)
		cpu_relax();
}

static bool test_init(void)
{
	int v = gic_init();

	if (!v) {
		printf("No supported gic present, skipping tests...\n");
		return false;
	}

	if (nr_cpus < 2) {
		printf("At least two cpus required, skipping tests...\n");
		return false;
	}

	switch (v) {
	case 2:
		vgic_dist_base = gicv2_dist_base();
		write_eoir = gicv2_write_eoir;
		break;
	case 3:
		vgic_dist_base = gicv3_dist_base();
		write_eoir = gicv3_write_eoir;
		break;
	}

	irq_ready = false;
	gic_enable_defaults();
	on_cpu_async(1, gic_secondary_entry, NULL);

	cntfrq = get_cntfrq();
	printf("Timer Frequency %d Hz (Output in microseconds)\n", cntfrq);

	return true;
}

static void gic_prep_common(void)
{
	unsigned tries = 1 << 28;

	while (!irq_ready && tries--)
		cpu_relax();
	assert(irq_ready);
}

static bool ipi_prep(void)
{
	u32 val;

	val = readl(vgic_dist_base + GICD_CTLR);
	if (readl(vgic_dist_base + GICD_TYPER2) & GICD_TYPER2_nASSGIcap) {
		/* nASSGIreq can be changed only when GICD is disabled */
		val &= ~GICD_CTLR_ENABLE_G1A;
		val &= ~GICD_CTLR_nASSGIreq;
		writel(val, vgic_dist_base + GICD_CTLR);
		gicv3_dist_wait_for_rwp();

		val |= GICD_CTLR_ENABLE_G1A;
		writel(val, vgic_dist_base + GICD_CTLR);
		gicv3_dist_wait_for_rwp();
	}

	nr_ipi_received = 0;
	gic_prep_common();
	return true;
}

static bool ipi_hw_prep(void)
{
	u32 val;

	val = readl(vgic_dist_base + GICD_CTLR);
	if (readl(vgic_dist_base + GICD_TYPER2) & GICD_TYPER2_nASSGIcap) {
		/* nASSGIreq can be changed only when GICD is disabled */
		val &= ~GICD_CTLR_ENABLE_G1A;
		val |= GICD_CTLR_nASSGIreq;
		writel(val, vgic_dist_base + GICD_CTLR);
		gicv3_dist_wait_for_rwp();

		val |= GICD_CTLR_ENABLE_G1A;
		writel(val, vgic_dist_base + GICD_CTLR);
		gicv3_dist_wait_for_rwp();
	} else {
		return false;
	}

	nr_ipi_received = 0;
	gic_prep_common();
	return true;
}

static void ipi_exec(void)
{
	unsigned tries = 1 << 28;

	irq_received = false;

	gic_ipi_send_single(1, 1);

	while (!irq_received && tries--)
		cpu_relax();

	if (irq_received)
		++nr_ipi_received;

	assert_msg(irq_received, "failed to receive IPI in time, but received %d successfully\n", nr_ipi_received);
}

static bool lpi_prep(void)
{
	struct its_collection *col1;
	struct its_device *dev2;

	if (!gicv3_its_base())
		return false;

	its_enable_defaults();
	dev2 = its_create_device(2 /* dev id */, 8 /* nb_ites */);
	col1 = its_create_collection(1 /* col id */, 1 /* target PE */);
	gicv3_lpi_set_config(8199, LPI_PROP_DEFAULT);

	its_send_mapd_nv(dev2, true);
	its_send_mapc_nv(col1, true);
	its_send_invall_nv(col1);
	its_send_mapti_nv(dev2, 8199 /* lpi id */, 20 /* event id */, col1);

	gic_prep_common();
	return true;
}

static void lpi_exec(void)
{
	struct its_device *dev2;
	unsigned tries = 1 << 28;
	static int received = 0;

	irq_received = false;

	dev2 = its_get_device(2);
	its_send_int_nv(dev2, 20);

	while (!irq_received && tries--)
		cpu_relax();

	if (irq_received)
		++received;

	assert_msg(irq_received, "failed to receive LPI in time, but received %d successfully\n", received);
}

static bool timer_prep(void)
{
	void *gic_isenabler;

	gic_enable_defaults();
	install_irq_handler(EL1H_IRQ, gic_irq_handler);
	local_irq_enable();

	switch (gic_version()) {
	case 2:
		gic_isenabler = gicv2_dist_base() + GICD_ISENABLER;
		break;
	case 3:
		gic_isenabler = gicv3_sgi_base() + GICR_ISENABLER0;
		break;
	default:
		assert_msg(0, "Unreachable");
	}

	writel(1 << PPI(TIMER_VTIMER_IRQ), gic_isenabler);
	write_sysreg(ARCH_TIMER_CTL_IMASK | ARCH_TIMER_CTL_ENABLE, cntv_ctl_el0);
	isb();

	gic_prep_common();
	return true;
}

static void timer_exec(void)
{
	u64 before_timer;
	u64 timer_10ms;
	unsigned tries = 1 << 28;
	static int received = 0;

	irq_received = false;

	before_timer = read_sysreg(cntvct_el0);
	timer_10ms = cntfrq / 100;
	write_sysreg(before_timer + timer_10ms, cntv_cval_el0);
	write_sysreg(ARCH_TIMER_CTL_ENABLE, cntv_ctl_el0);
	isb();

	while (!irq_received && tries--)
		cpu_relax();

	if (irq_received)
		++received;

	assert_msg(irq_received, "failed to receive PPI in time, but received %d successfully\n", received);
}

static void timer_post(uint64_t ntimes, uint64_t *total_ticks)
{
	/*
	 * We use a 10msec timer to test the latency of PPI,
	 * so we substract the ticks of 10msec to get the
	 * actual latency
	 */
	*total_ticks -= ntimes * (cntfrq / 100);
}

static void hvc_exec(void)
{
	asm volatile("mov w0, #0x4b000000; hvc #0" ::: "w0");
}

static void *userspace_emulated_addr;

static bool mmio_read_user_prep(void)
{
	/*
	 * FIXME: Read device-id in virtio mmio here in order to
	 * force an exit to userspace. This address needs to be
	 * updated in the future if any relevant changes in QEMU
	 * test-dev are made.
	 */
	userspace_emulated_addr = (void*)ioremap(0x0a000008, sizeof(u32));
	return true;
}

static void mmio_read_user_exec(void)
{
	readl(userspace_emulated_addr);
}

static void mmio_read_vgic_exec(void)
{
	readl(vgic_dist_base + GICD_IIDR);
}

static void eoi_exec(void)
{
	int spurious_id = 1023; /* writes to EOI are ignored */

	/* Avoid measuring assert(..) in gic_write_eoir */
	write_eoir(spurious_id);
}

struct exit_test {
	const char *name;
	bool (*prep)(void);
	void (*exec)(void);
	void (*post)(uint64_t ntimes, uint64_t *total_ticks);
	u32 times;
	bool run;
};

static struct exit_test tests[] = {
	{"hvc",			NULL,			hvc_exec,		NULL,		65536,		true},
	{"mmio_read_user",	mmio_read_user_prep,	mmio_read_user_exec,	NULL,		65536,		true},
	{"mmio_read_vgic",	NULL,			mmio_read_vgic_exec,	NULL,		65536,		true},
	{"eoi",			NULL,			eoi_exec,		NULL,		65536,		true},
	{"ipi",			ipi_prep,		ipi_exec,		NULL,		65536,		true},
	{"ipi_hw",		ipi_hw_prep,		ipi_exec,		NULL,		65536,		true},
	{"lpi",			lpi_prep,		lpi_exec,		NULL,		65536,		true},
	{"timer_10ms",		timer_prep,		timer_exec,		timer_post,	256,		true},
};

struct ns_time {
	uint64_t ns;
	uint64_t ns_frac;
};

#define PS_PER_SEC (1000 * 1000 * 1000 * 1000UL)
static void ticks_to_ns_time(uint64_t ticks, struct ns_time *ns_time)
{
	uint64_t ps_per_tick = PS_PER_SEC / cntfrq + !!(PS_PER_SEC % cntfrq);
	uint64_t ps;

	ps = ticks * ps_per_tick;
	ns_time->ns = ps / 1000;
	ns_time->ns_frac = (ps % 1000) / 100;
}

static void loop_test(struct exit_test *test)
{
	uint64_t start, end, total_ticks, ntimes = 0;
	struct ns_time avg_ns, total_ns = {};

	total_ticks = 0;
	if (test->prep) {
		if(!test->prep()) {
			printf("%s test skipped\n", test->name);
			return;
		}
	}

	while (ntimes < test->times && total_ns.ns < NS_5_SECONDS) {
		isb();
		start = read_sysreg(cntpct_el0);
		test->exec();
		isb();
		end = read_sysreg(cntpct_el0);

		ntimes++;
		total_ticks += (end - start);
		ticks_to_ns_time(total_ticks, &total_ns);
	}

	if (test->post) {
		test->post(ntimes, &total_ticks);
		ticks_to_ns_time(total_ticks, &total_ns);
	}

	avg_ns.ns = total_ns.ns / ntimes;
	avg_ns.ns_frac = total_ns.ns_frac / ntimes;

	printf("%-30s%15" PRId64 ".%-15" PRId64 "%15" PRId64 ".%-15" PRId64 "\n",
		test->name, total_ns.ns, total_ns.ns_frac, avg_ns.ns, avg_ns.ns_frac);
}

int main(int argc, char **argv)
{
	int i;

	if (!test_init())
		return 1;

	printf("\n%-30s%18s%13s%18s%13s\n", "name", "total ns", "", "avg ns", "");
	for (i = 0 ; i < 92; ++i)
		printf("%c", '-');
	printf("\n");
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!tests[i].run)
			continue;
		assert(tests[i].name && tests[i].exec);
		loop_test(&tests[i]);
	}

	return 0;
}
