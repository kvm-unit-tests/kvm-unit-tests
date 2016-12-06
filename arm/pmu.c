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

#define PMU_PMCR_E         (1 << 0)
#define PMU_PMCR_C         (1 << 2)
#define PMU_PMCR_LC        (1 << 6)
#define PMU_PMCR_N_SHIFT   11
#define PMU_PMCR_N_MASK    0x1f
#define PMU_PMCR_ID_SHIFT  16
#define PMU_PMCR_ID_MASK   0xff
#define PMU_PMCR_IMP_SHIFT 24
#define PMU_PMCR_IMP_MASK  0xff

#define ID_DFR0_PERFMON_SHIFT 24
#define ID_DFR0_PERFMON_MASK  0xf

#define PMU_CYCLE_IDX         31

#define NR_SAMPLES 10

static unsigned int pmu_version;
#if defined(__arm__)
#define PMCR         __ACCESS_CP15(c9, 0, c12, 0)
#define ID_DFR0      __ACCESS_CP15(c0, 0, c1, 2)
#define PMSELR       __ACCESS_CP15(c9, 0, c12, 5)
#define PMXEVTYPER   __ACCESS_CP15(c9, 0, c13, 1)
#define PMCNTENSET   __ACCESS_CP15(c9, 0, c12, 1)
#define PMCCNTR32    __ACCESS_CP15(c9, 0, c13, 0)
#define PMCCNTR64    __ACCESS_CP15_64(0, c9)

static inline uint32_t get_id_dfr0(void) { return read_sysreg(ID_DFR0); }
static inline uint32_t get_pmcr(void) { return read_sysreg(PMCR); }
static inline void set_pmcr(uint32_t v) { write_sysreg(v, PMCR); }
static inline void set_pmcntenset(uint32_t v) { write_sysreg(v, PMCNTENSET); }

static inline uint64_t get_pmccntr(void)
{
	if (pmu_version == 0x3)
		return read_sysreg(PMCCNTR64);
	else
		return read_sysreg(PMCCNTR32);
}

/* PMCCFILTR is an obsolete name for PMXEVTYPER31 in ARMv7 */
static inline void set_pmccfiltr(uint32_t value)
{
	write_sysreg(PMU_CYCLE_IDX, PMSELR);
	write_sysreg(value, PMXEVTYPER);
	isb();
}
#elif defined(__aarch64__)
static inline uint32_t get_id_dfr0(void) { return read_sysreg(id_dfr0_el1); }
static inline uint32_t get_pmcr(void) { return read_sysreg(pmcr_el0); }
static inline void set_pmcr(uint32_t v) { write_sysreg(v, pmcr_el0); }
static inline uint64_t get_pmccntr(void) { return read_sysreg(pmccntr_el0); }
static inline void set_pmcntenset(uint32_t v) { write_sysreg(v, pmcntenset_el0); }
static inline void set_pmccfiltr(uint32_t v) { write_sysreg(v, pmccfiltr_el0); }
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

/*
 * Ensure that the cycle counter progresses between back-to-back reads.
 */
static bool check_cycles_increase(void)
{
	bool success = true;

	/* init before event access, this test only cares about cycle count */
	set_pmcntenset(1 << PMU_CYCLE_IDX);
	set_pmccfiltr(0); /* count cycles in EL0, EL1, but not EL2 */

	set_pmcr(get_pmcr() | PMU_PMCR_LC | PMU_PMCR_C | PMU_PMCR_E);

	for (int i = 0; i < NR_SAMPLES; i++) {
		uint64_t a, b;

		a = get_pmccntr();
		b = get_pmccntr();

		if (a >= b) {
			printf("Read %"PRId64" then %"PRId64".\n", a, b);
			success = false;
			break;
		}
	}

	set_pmcr(get_pmcr() & ~PMU_PMCR_E);

	return success;
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
	report("Monotonically increasing cycle count", check_cycles_increase());

	return report_summary();
}
