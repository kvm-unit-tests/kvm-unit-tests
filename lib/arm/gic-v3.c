/*
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/gic.h>
#include <asm/io.h>

void gicv3_set_redist_base(size_t stride)
{
	u32 aff = mpidr_compress(get_mpidr());
	void *ptr = gicv3_data.redist_base[0];
	u64 typer;

	do {
		typer = gicv3_read_typer(ptr + GICR_TYPER);
		if ((typer >> 32) == aff) {
			gicv3_redist_base() = ptr;
			return;
		}
		ptr += stride; /* skip RD_base, SGI_base, etc. */
	} while (!(typer & GICR_TYPER_LAST));

	/* should never reach here */
	assert(0);
}

void gicv3_enable_defaults(void)
{
	void *dist = gicv3_dist_base();
	void *sgi_base;
	unsigned int i;

	gicv3_data.irq_nr = GICD_TYPER_IRQS(readl(dist + GICD_TYPER));
	if (gicv3_data.irq_nr > 1020)
		gicv3_data.irq_nr = 1020;

	writel(0, dist + GICD_CTLR);
	gicv3_dist_wait_for_rwp();

	writel(GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A | GICD_CTLR_ENABLE_G1,
	       dist + GICD_CTLR);
	gicv3_dist_wait_for_rwp();

	for (i = 0; i < gicv3_data.irq_nr; i += 4)
		writel(~0, dist + GICD_IGROUPR + i);

	if (!gicv3_redist_base())
		gicv3_set_redist_base(SZ_64K * 2);
	sgi_base = gicv3_sgi_base();

	writel(~0, sgi_base + GICR_IGROUPR0);

	for (i = 0; i < 16; i += 4)
		writel(GICD_INT_DEF_PRI_X4, sgi_base + GICR_IPRIORITYR0 + i);

	writel(GICD_INT_EN_SET_SGI, sgi_base + GICR_ISENABLER0);

	gicv3_write_pmr(GICC_INT_PRI_THRESHOLD);
	gicv3_write_grpen1(1);
}
