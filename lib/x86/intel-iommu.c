/*
 * Intel IOMMU APIs
 *
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Authors:
 *   Peter Xu <peterx@redhat.com>,
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or
 * later.
 */

#include "intel-iommu.h"

#define VTD_RTA_MASK  (PAGE_MASK)
#define VTD_IRTA_MASK (PAGE_MASK)

void *vtd_reg_base;

static uint64_t vtd_root_table(void)
{
	/* No extend root table support yet */
	return vtd_readq(DMAR_RTADDR_REG) & VTD_RTA_MASK;
}

static uint64_t vtd_ir_table(void)
{
	return vtd_readq(DMAR_IRTA_REG) & VTD_IRTA_MASK;
}

static void vtd_gcmd_or(uint32_t cmd)
{
	uint32_t status;

	/* We only allow set one bit for each time */
	assert(is_power_of_2(cmd));

	status = vtd_readl(DMAR_GSTS_REG);
	vtd_writel(DMAR_GCMD_REG, status | cmd);

	if (cmd & VTD_GCMD_ONE_SHOT_BITS) {
		/* One-shot bits are taking effect immediately */
		return;
	}

	/* Make sure IOMMU handled our command request */
	while (!(vtd_readl(DMAR_GSTS_REG) & cmd))
		cpu_relax();
}

static void vtd_dump_init_info(void)
{
	uint32_t version;

	version = vtd_readl(DMAR_VER_REG);

	/* Major version >= 1 */
	assert(((version >> 3) & 0xf) >= 1);

	printf("VT-d version:   0x%x\n", version);
	printf("     cap:       0x%016lx\n", vtd_readq(DMAR_CAP_REG));
	printf("     ecap:      0x%016lx\n", vtd_readq(DMAR_ECAP_REG));
}

static void vtd_setup_root_table(void)
{
	void *root = alloc_page();

	memset(root, 0, PAGE_SIZE);
	vtd_writeq(DMAR_RTADDR_REG, virt_to_phys(root));
	vtd_gcmd_or(VTD_GCMD_ROOT);
	printf("DMAR table address: 0x%016lx\n", vtd_root_table());
}

static void vtd_setup_ir_table(void)
{
	void *root = alloc_page();

	memset(root, 0, PAGE_SIZE);
	/* 0xf stands for table size (2^(0xf+1) == 65536) */
	vtd_writeq(DMAR_IRTA_REG, virt_to_phys(root) | 0xf);
	vtd_gcmd_or(VTD_GCMD_IR_TABLE);
	printf("IR table address: 0x%016lx\n", vtd_ir_table());
}

void vtd_init(void)
{
	setup_vm();
	smp_init();

	vtd_reg_base = ioremap(Q35_HOST_BRIDGE_IOMMU_ADDR, PAGE_SIZE);

	vtd_dump_init_info();
	vtd_gcmd_or(VTD_GCMD_QI); /* Enable QI */
	vtd_setup_root_table();
	vtd_setup_ir_table();
	vtd_gcmd_or(VTD_GCMD_DMAR); /* Enable DMAR */
	vtd_gcmd_or(VTD_GCMD_IR);   /* Enable IR */
}
