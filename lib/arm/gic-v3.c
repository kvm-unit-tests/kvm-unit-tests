/*
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/gic.h>
#include <asm/io.h>
#include <alloc_page.h>

void gicv3_set_redist_base(size_t stride)
{
	u32 aff = mpidr_compress(get_mpidr());
	u64 typer;
	int i = 0;

	while (gicv3_data.redist_bases[i]) {
		void *ptr = gicv3_data.redist_bases[i];
		do {
			typer = gicv3_read_typer(ptr + GICR_TYPER);
			if ((typer >> 32) == aff) {
				gicv3_redist_base() = ptr;
				return;
			}
			ptr += stride; /* skip RD_base, SGI_base, etc. */
		} while (!(typer & GICR_TYPER_LAST));
		++i;
	}

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

u32 gicv3_iar_irqnr(u32 iar)
{
	return iar & ((1 << 24) - 1);
}

void gicv3_ipi_send_mask(int irq, const cpumask_t *dest)
{
	u16 tlist;
	int cpu;

	assert(irq < 16);

	/*
	 * Ensure stores to Normal memory are visible to other CPUs before
	 * sending the IPI.
	 */
	wmb();

	/*
	 * For each cpu in the mask collect its peers, which are also in
	 * the mask, in order to form target lists.
	 */
	for_each_cpu(cpu, dest) {
		u64 mpidr = cpus[cpu], sgi1r;
		u64 cluster_id;

		/*
		 * GICv3 can send IPIs to up 16 peer cpus with a single
		 * write to ICC_SGI1R_EL1 (using the target list). Peers
		 * are cpus that have nearly identical MPIDRs, the only
		 * difference being Aff0. The matching upper affinity
		 * levels form the cluster ID.
		 */
		cluster_id = mpidr & ~0xffUL;
		tlist = 0;

		/*
		 * Sort of open code for_each_cpu in order to have a
		 * nested for_each_cpu loop.
		 */
		while (cpu < nr_cpus) {
			if ((mpidr & 0xff) >= 16) {
				printf("cpu%d MPIDR:aff0 is %d (>= 16)!\n",
					cpu, (int)(mpidr & 0xff));
				break;
			}

			tlist |= 1 << (mpidr & 0xf);

			cpu = cpumask_next(cpu, dest);
			if (cpu >= nr_cpus)
				break;

			mpidr = cpus[cpu];

			if (cluster_id != (mpidr & ~0xffUL)) {
				/*
				 * The next cpu isn't in our cluster. Roll
				 * back the cpu index allowing the outer
				 * for_each_cpu to find it again with
				 * cpumask_next
				 */
				--cpu;
				break;
			}
		}

		/* Send the IPIs for the target list of this cluster */
		sgi1r = (MPIDR_TO_SGI_AFFINITY(cluster_id, 3)	|
			 MPIDR_TO_SGI_AFFINITY(cluster_id, 2)	|
			 irq << 24				|
			 MPIDR_TO_SGI_AFFINITY(cluster_id, 1)	|
			 tlist);

		gicv3_write_sgi1r(sgi1r);
	}

	/* Force the above writes to ICC_SGI1R_EL1 to be executed */
	isb();
}

void gicv3_ipi_send_single(int irq, int cpu)
{
	cpumask_t dest;

	cpumask_clear(&dest);
	cpumask_set_cpu(cpu, &dest);
	gicv3_ipi_send_mask(irq, &dest);
}

#if defined(__aarch64__)

/*
 * alloc_lpi_tables - Allocate LPI config and pending tables
 * and set PROPBASER (shared by all rdistributors) and per
 * redistributor PENDBASER.
 *
 * gicv3_set_redist_base() must be called before
 */
void gicv3_lpi_alloc_tables(void)
{
	unsigned long n = SZ_64K >> PAGE_SHIFT;
	unsigned long order = fls(n);
	u64 prop_val;
	int cpu;

	assert(gicv3_redist_base());

	gicv3_data.lpi_prop = alloc_pages(order);

	/* ID bits = 13, ie. up to 14b LPI INTID */
	prop_val = (u64)(virt_to_phys(gicv3_data.lpi_prop)) | 13;

	for_each_present_cpu(cpu) {
		u64 pend_val;
		void *ptr;

		ptr = gicv3_data.redist_base[cpu];

		writeq(prop_val, ptr + GICR_PROPBASER);

		gicv3_data.lpi_pend[cpu] = alloc_pages(order);
		pend_val = (u64)(virt_to_phys(gicv3_data.lpi_pend[cpu]));
		writeq(pend_val, ptr + GICR_PENDBASER);
	}
}

void gicv3_lpi_set_clr_pending(int rdist, int n, bool set)
{
	u8 *ptr = gicv3_data.lpi_pend[rdist];
	u8 mask = 1 << (n % 8), byte;

	ptr += (n / 8);
	byte = *ptr;
	if (set)
		byte |=  mask;
	else
		byte &= ~mask;
	*ptr = byte;
}

static void gicv3_lpi_rdist_ctrl(u32 redist, bool set)
{
	void *ptr;
	u64 val;

	assert(redist < nr_cpus);

	ptr = gicv3_data.redist_base[redist];
	val = readl(ptr + GICR_CTLR);
	if (set)
		val |= GICR_CTLR_ENABLE_LPIS;
	else
		val &= ~GICR_CTLR_ENABLE_LPIS;
	writel(val,  ptr + GICR_CTLR);
}

void gicv3_lpi_rdist_enable(int redist)
{
	gicv3_lpi_rdist_ctrl(redist, true);
}
void gicv3_lpi_rdist_disable(int redist)
{
	gicv3_lpi_rdist_ctrl(redist, false);
}
#endif /* __aarch64__ */
