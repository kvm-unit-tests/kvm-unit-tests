/*
 * Verify PL031 functionality
 *
 * This test verifies whether the emulated PL031 behaves correctly.
 *
 * Copyright 2019 Amazon.com, Inc. or its affiliates.
 * Author: Alexander Graf <graf@amazon.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <devicetree.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/gic.h>

struct pl031_regs {
	uint32_t dr;	/* Data Register */
	uint32_t mr;	/* Match Register */
	uint32_t lr;	/* Load Register */
	union {
		uint8_t cr;	/* Control Register */
		uint32_t cr32;
	};
	union {
		uint8_t imsc;	/* Interrupt Mask Set or Clear register */
		uint32_t imsc32;
	};
	union {
		uint8_t ris;	/* Raw Interrupt Status */
		uint32_t ris32;
	};
	union {
		uint8_t mis;	/* Masked Interrupt Status */
		uint32_t mis32;
	};
	union {
		uint8_t icr;	/* Interrupt Clear Register */
		uint32_t icr32;
	};
	uint32_t reserved[1008];
	uint32_t periph_id[4];
	uint32_t pcell_id[4];
};

static u32 cntfrq;
static struct pl031_regs *pl031;
static int pl031_irq;
static void *gic_ispendr;
static void *gic_isenabler;
static volatile bool irq_triggered;

static int check_id(void)
{
	uint32_t id[] = { 0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1 };
	int i;

	for (i = 0; i < ARRAY_SIZE(id); i++)
		if (id[i] != readl(&pl031->periph_id[i]))
			return 1;

	return 0;
}

static int check_ro(void)
{
	uint32_t offs[] = { offsetof(struct pl031_regs, ris),
			    offsetof(struct pl031_regs, mis),
			    offsetof(struct pl031_regs, periph_id[0]),
			    offsetof(struct pl031_regs, periph_id[1]),
			    offsetof(struct pl031_regs, periph_id[2]),
			    offsetof(struct pl031_regs, periph_id[3]),
			    offsetof(struct pl031_regs, pcell_id[0]),
			    offsetof(struct pl031_regs, pcell_id[1]),
			    offsetof(struct pl031_regs, pcell_id[2]),
			    offsetof(struct pl031_regs, pcell_id[3]) };
	int i;

	for (i = 0; i < ARRAY_SIZE(offs); i++) {
		uint32_t before32;
		uint16_t before16;
		uint8_t before8;
		void *addr = (void*)pl031 + offs[i];
		uint32_t poison = 0xdeadbeefULL;

		before8 = readb(addr);
		before16 = readw(addr);
		before32 = readl(addr);

		writeb(poison, addr);
		writew(poison, addr);
		writel(poison, addr);

		if (before8 != readb(addr))
			return 1;
		if (before16 != readw(addr))
			return 1;
		if (before32 != readl(addr))
			return 1;
	}

	return 0;
}

static int check_rtc_freq(void)
{
	uint32_t seconds_to_wait = 2;
	uint32_t before = readl(&pl031->dr);
	uint64_t before_tick = get_cntvct();
	uint64_t target_tick = before_tick + (cntfrq * seconds_to_wait);

	/* Wait for 2 seconds */
	while (get_cntvct() < target_tick) ;

	if (readl(&pl031->dr) != before + seconds_to_wait)
		return 1;

	return 0;
}

static bool gic_irq_pending(void)
{
	uint32_t offset = (pl031_irq / 32) * 4;

	return readl(gic_ispendr + offset) & (1 << (pl031_irq & 31));
}

static void gic_irq_unmask(void)
{
	uint32_t offset = (pl031_irq / 32) * 4;

	writel(1 << (pl031_irq & 31), gic_isenabler + offset);
}

static void irq_handler(struct pt_regs *regs)
{
	u32 irqstat = gic_read_iar();
	u32 irqnr = gic_iar_irqnr(irqstat);

	gic_write_eoir(irqstat);

	if (irqnr == pl031_irq) {
		report(readl(&pl031->ris) == 1, "  RTC RIS == 1");
		report(readl(&pl031->mis) == 1, "  RTC MIS == 1");

		/* Writing one to bit zero should clear IRQ status */
		writel(1, &pl031->icr);

		report(readl(&pl031->ris) == 0, "  RTC RIS == 0");
		report(readl(&pl031->mis) == 0, "  RTC MIS == 0");
		irq_triggered = true;
	} else {
		report_info("Unexpected interrupt: %"PRIu32"\n", irqnr);
		return;
	}
}

static int check_rtc_irq(void)
{
	uint32_t seconds_to_wait = 1;
	uint32_t before = readl(&pl031->dr);
	uint64_t before_tick = get_cntvct();
	uint64_t target_tick = before_tick + (cntfrq * (seconds_to_wait + 1));

	report_info("Checking IRQ trigger (MR)");

	irq_triggered = false;

	/* Fire IRQ in 1 second */
	writel(before + seconds_to_wait, &pl031->mr);

#ifdef __aarch64__
	install_irq_handler(EL1H_IRQ, irq_handler);
#else
	install_exception_handler(EXCPTN_IRQ, irq_handler);
#endif

	/* Wait until 2 seconds are over */
	while (get_cntvct() < target_tick) ;

	report(!gic_irq_pending(), "  RTC IRQ not delivered without mask");

	/* Mask the IRQ so that it gets delivered */
	writel(1, &pl031->imsc);
	report(gic_irq_pending(), "  RTC IRQ pending now");

	/* Enable retrieval of IRQ */
	gic_irq_unmask();
	local_irq_enable();

	report(irq_triggered, "  IRQ triggered");
	report(!gic_irq_pending(), "  RTC IRQ not pending anymore");
	if (!irq_triggered) {
		report_info("  RTC RIS: %"PRIx32, readl(&pl031->ris));
		report_info("  RTC MIS: %"PRIx32, readl(&pl031->mis));
		report_info("  RTC IMSC: %"PRIx32, readl(&pl031->imsc));
		report_info("  GIC IRQs pending: %08"PRIx32" %08"PRIx32, readl(gic_ispendr), readl(gic_ispendr + 4));
	}

	local_irq_disable();
	return 0;
}

static void rtc_irq_init(void)
{
	gic_enable_defaults();

	switch (gic_version()) {
	case 2:
		gic_ispendr = gicv2_dist_base() + GICD_ISPENDR;
		gic_isenabler = gicv2_dist_base() + GICD_ISENABLER;
		break;
	case 3:
		gic_ispendr = gicv3_dist_base() + GICD_ISPENDR;
		gic_isenabler = gicv3_dist_base() + GICD_ISENABLER;
		break;
	}
}

static int rtc_fdt_init(void)
{
	const struct fdt_property *prop;
	const void *fdt = dt_fdt();
	struct dt_pbus_reg base;
	int node, len;
	u32 *data;
	int ret;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,pl031");
	if (node < 0)
		return -1;

	prop = fdt_get_property(fdt, node, "interrupts", &len);
	assert(prop && len == (3 * sizeof(u32)));
	data = (u32 *)prop->data;
	assert(data[0] == 0); /* SPI */
	pl031_irq = SPI(fdt32_to_cpu(data[1]));

	ret = dt_pbus_translate_node(node, 0, &base);
	assert(!ret);
	pl031 = ioremap(base.addr, base.size);

	return 0;
}

int main(int argc, char **argv)
{
	cntfrq = get_cntfrq();
	rtc_irq_init();
	if (rtc_fdt_init()) {
		report_skip("Skipping PL031 tests. No device present.");
		return 0;
	}

	report_prefix_push("pl031");
	report(!check_id(), "Periph/PCell IDs match");
	report(!check_ro(), "R/O fields are R/O");
	report(!check_rtc_freq(), "RTC ticks at 1HZ");
	report(!gic_irq_pending(), "RTC IRQ not pending yet");
	check_rtc_irq();

	return report_summary();
}
