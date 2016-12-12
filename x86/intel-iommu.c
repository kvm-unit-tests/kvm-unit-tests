/*
 * Intel IOMMU unit test.
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

int main(int argc, char *argv[])
{
	vtd_init();

	report("fault status check", vtd_readl(DMAR_FSTS_REG) == 0);
	report("QI enablement", vtd_readl(DMAR_GSTS_REG) & VTD_GCMD_QI);
	report("DMAR table setup", vtd_readl(DMAR_GSTS_REG) & VTD_GCMD_ROOT);
	report("IR table setup", vtd_readl(DMAR_GSTS_REG) & VTD_GCMD_IR_TABLE);
	report("DMAR enablement", vtd_readl(DMAR_GSTS_REG) & VTD_GCMD_DMAR);
	report("IR enablement", vtd_readl(DMAR_GSTS_REG) & VTD_GCMD_IR);

	return report_summary();
}
