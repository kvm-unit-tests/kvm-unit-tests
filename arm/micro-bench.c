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

#define NTIMES (1U << 16)

static u32 cntfrq;

static volatile bool irq_ready, irq_received;
static int nr_ipi_received;

static void *vgic_dist_base;
static void (*write_eoir)(u32 irqstat);

static void gic_irq_handler(struct pt_regs *regs)
{
	irq_ready = false;
	irq_received = true;
	gic_write_eoir(gic_read_iar());
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

static void hvc_exec(void)
{
	asm volatile("mov w0, #0x4b000000; hvc #0" ::: "w0");
}

static void mmio_read_user_exec(void)
{
	/*
	 * FIXME: Read device-id in virtio mmio here in order to
	 * force an exit to userspace. This address needs to be
	 * updated in the future if any relevant changes in QEMU
	 * test-dev are made.
	 */
	void *userspace_emulated_addr = (void*)0x0a000008;

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
	bool run;
};

static struct exit_test tests[] = {
	{"hvc",			NULL,		hvc_exec,		true},
	{"mmio_read_user",	NULL,		mmio_read_user_exec,	true},
	{"mmio_read_vgic",	NULL,		mmio_read_vgic_exec,	true},
	{"eoi",			NULL,		eoi_exec,		true},
	{"ipi",			ipi_prep,	ipi_exec,		true},
	{"ipi_hw",		ipi_hw_prep,	ipi_exec,		true},
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
	uint64_t start, end, total_ticks, ntimes = NTIMES;
	struct ns_time total_ns, avg_ns;

	if (test->prep) {
		if(!test->prep()) {
			printf("%s test skipped\n", test->name);
			return;
		}
	}
	isb();
	start = read_sysreg(cntpct_el0);
	while (ntimes--)
		test->exec();
	isb();
	end = read_sysreg(cntpct_el0);

	total_ticks = end - start;
	ticks_to_ns_time(total_ticks, &total_ns);
	avg_ns.ns = total_ns.ns / NTIMES;
	avg_ns.ns_frac = total_ns.ns_frac / NTIMES;

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
