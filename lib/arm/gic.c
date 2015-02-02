/*
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <devicetree.h>
#include <asm/gic.h>
#include <asm/io.h>

struct gicv2_data gicv2_data;

/*
 * Documentation/devicetree/bindings/interrupt-controller/arm,gic.txt
 */
static bool
gic_get_dt_bases(const char *compatible, void **base1, void **base2)
{
	struct dt_pbus_reg reg;
	struct dt_device gic;
	struct dt_bus bus;
	int node, ret;

	dt_bus_init_defaults(&bus);
	dt_device_init(&gic, &bus, NULL);

	node = dt_device_find_compatible(&gic, compatible);
	assert(node >= 0 || node == -FDT_ERR_NOTFOUND);

	if (node == -FDT_ERR_NOTFOUND)
		return false;

	dt_device_bind_node(&gic, node);

	ret = dt_pbus_translate(&gic, 0, &reg);
	assert(ret == 0);
	*base1 = ioremap(reg.addr, reg.size);

	ret = dt_pbus_translate(&gic, 1, &reg);
	assert(ret == 0);
	*base2 = ioremap(reg.addr, reg.size);

	return true;
}

int gicv2_init(void)
{
	return gic_get_dt_bases("arm,cortex-a15-gic",
			&gicv2_data.dist_base, &gicv2_data.cpu_base);
}

int gic_init(void)
{
	if (gicv2_init())
		return 2;
	return 0;
}

void gicv2_enable_defaults(void)
{
	void *dist = gicv2_dist_base();
	void *cpu_base = gicv2_cpu_base();
	unsigned int i;

	gicv2_data.irq_nr = GICD_TYPER_IRQS(readl(dist + GICD_TYPER));
	if (gicv2_data.irq_nr > 1020)
		gicv2_data.irq_nr = 1020;

	for (i = 0; i < gicv2_data.irq_nr; i += 4)
		writel(GICD_INT_DEF_PRI_X4, dist + GICD_IPRIORITYR + i);

	writel(GICD_INT_EN_SET_SGI, dist + GICD_ISENABLER + 0);
	writel(GICD_ENABLE, dist + GICD_CTLR);

	writel(GICC_INT_PRI_THRESHOLD, cpu_base + GICC_PMR);
	writel(GICC_ENABLE, cpu_base + GICC_CTLR);
}
