/*
 * Test the ARM Performance Monitors Unit (PMU).
 *
 * Copyright (c) 2015-2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2016, Red Hat Inc, Wei Huang <wei@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 and
 * only version 2.1 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 */
#include "libcflat.h"
#include "asm/barrier.h"
#include "asm/sysreg.h"
#include "asm/processor.h"

#define PMU_PMCR_N_SHIFT   11
#define PMU_PMCR_N_MASK    0x1f
#define PMU_PMCR_ID_SHIFT  16
#define PMU_PMCR_ID_MASK   0xff
#define PMU_PMCR_IMP_SHIFT 24
#define PMU_PMCR_IMP_MASK  0xff

#define ID_DFR0_PERFMON_SHIFT 24
#define ID_DFR0_PERFMON_MASK  0xf

static unsigned int pmu_version;
#if defined(__arm__)
#define PMCR         __ACCESS_CP15(c9, 0, c12, 0)
#define ID_DFR0      __ACCESS_CP15(c0, 0, c1, 2)

static inline uint32_t get_id_dfr0(void) { return read_sysreg(ID_DFR0); }
static inline uint32_t get_pmcr(void) { return read_sysreg(PMCR); }
#elif defined(__aarch64__)
static inline uint32_t get_id_dfr0(void) { return read_sysreg(id_dfr0_el1); }
static inline uint32_t get_pmcr(void) { return read_sysreg(pmcr_el0); }
#endif

/*
 * As a simple sanity check on the PMCR_EL0, ensure the implementer field isn't
 * null. Also print out a couple other interesting fields for diagnostic
 * purposes. For example, as of fall 2016, QEMU TCG mode doesn't implement
 * event counters and therefore reports zero event counters, but hopefully
 * support for at least the instructions event will be added in the future and
 * the reported number of event counters will become nonzero.
 */
static bool check_pmcr(void)
{
	uint32_t pmcr;

	pmcr = get_pmcr();

	report_info("PMU implementer/ID code/counters: 0x%x(\"%c\")/0x%x/%d",
		    (pmcr >> PMU_PMCR_IMP_SHIFT) & PMU_PMCR_IMP_MASK,
		    ((pmcr >> PMU_PMCR_IMP_SHIFT) & PMU_PMCR_IMP_MASK) ? : ' ',
		    (pmcr >> PMU_PMCR_ID_SHIFT) & PMU_PMCR_ID_MASK,
		    (pmcr >> PMU_PMCR_N_SHIFT) & PMU_PMCR_N_MASK);

	return ((pmcr >> PMU_PMCR_IMP_SHIFT) & PMU_PMCR_IMP_MASK) != 0;
}

/* Return FALSE if no PMU found, otherwise return TRUE */
bool pmu_probe(void)
{
	uint32_t dfr0;

	/* probe pmu version */
	dfr0 = get_id_dfr0();
	pmu_version = (dfr0 >> ID_DFR0_PERFMON_SHIFT) & ID_DFR0_PERFMON_MASK;

	if (pmu_version)
		report_info("PMU version: %d", pmu_version);

	return pmu_version;
}

int main(void)
{
	if (!pmu_probe()) {
		printf("No PMU found, test skipped...\n");
		return report_summary();
	}

	report_prefix_push("pmu");

	report("Control register", check_pmcr());

	return report_summary();
}
