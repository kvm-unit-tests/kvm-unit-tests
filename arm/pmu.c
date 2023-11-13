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
#include "errata.h"
#include "asm/barrier.h"
#include "asm/sysreg.h"
#include "asm/processor.h"
#include <bitops.h>
#include <asm/gic.h>

#define PMU_PMCR_E         (1 << 0)
#define PMU_PMCR_P         (1 << 1)
#define PMU_PMCR_C         (1 << 2)
#define PMU_PMCR_D         (1 << 3)
#define PMU_PMCR_X         (1 << 4)
#define PMU_PMCR_DP        (1 << 5)
#define PMU_PMCR_LC        (1 << 6)
#define PMU_PMCR_LP        (1 << 7)
#define PMU_PMCR_N_SHIFT   11
#define PMU_PMCR_N_MASK    0x1f
#define PMU_PMCR_ID_SHIFT  16
#define PMU_PMCR_ID_MASK   0xff
#define PMU_PMCR_IMP_SHIFT 24
#define PMU_PMCR_IMP_MASK  0xff

#define PMU_CYCLE_IDX      31

#define NR_SAMPLES 10

/* Some PMU events */
#define SW_INCR			0x0
#define INST_RETIRED		0x8
#define CPU_CYCLES		0x11
#define MEM_ACCESS		0x13
#define INST_PREC		0x1B
#define STALL_FRONTEND		0x23
#define STALL_BACKEND		0x24
#define CHAIN			0x1E

#define COMMON_EVENTS_LOW	0x0
#define COMMON_EVENTS_HIGH	0x3F
#define EXT_COMMON_EVENTS_LOW	0x4000
#define EXT_COMMON_EVENTS_HIGH	0x403F

#define ALL_SET_32		0x00000000FFFFFFFFULL
#define ALL_SET_64		0xFFFFFFFFFFFFFFFFULL

#define ALL_SET(__overflow_at_64bits)				\
	(__overflow_at_64bits ? ALL_SET_64 : ALL_SET_32)

#define ALL_CLEAR		0x0000000000000000ULL
#define PRE_OVERFLOW_32		0x00000000FFFFFFF0ULL
#define PRE_OVERFLOW_64		0xFFFFFFFFFFFFFFF0ULL
#define COUNT 250
#define MARGIN 100
#define COUNT_INT 1000
/*
 * PRE_OVERFLOW2 is set so that 1st @COUNT iterations do not
 * produce 32b overflow and 2nd @COUNT iterations do. To accommodate
 * for some observed variability we take into account a given @MARGIN
 */
#define PRE_OVERFLOW2_32		(ALL_SET_32 - COUNT - MARGIN)
#define PRE_OVERFLOW2_64		(ALL_SET_64 - COUNT - MARGIN)

#define PRE_OVERFLOW2(__overflow_at_64bits)				\
	(__overflow_at_64bits ? PRE_OVERFLOW2_64 : PRE_OVERFLOW2_32)

#define PRE_OVERFLOW(__overflow_at_64bits)				\
	(__overflow_at_64bits ? PRE_OVERFLOW_64 : PRE_OVERFLOW_32)

#define PMU_PPI			23

struct pmu {
	unsigned int version;
	unsigned int nb_implemented_counters;
	uint32_t pmcr_ro;
};

struct pmu_stats {
	unsigned long bitmap;
	uint32_t interrupts[32];
	bool unexpected;
};

static struct pmu pmu;

#if defined(__arm__)
#define ID_DFR0_PERFMON_SHIFT 24
#define ID_DFR0_PERFMON_MASK  0xf

#define ID_DFR0_PMU_NOTIMPL	0b0000
#define ID_DFR0_PMU_V1		0b0001
#define ID_DFR0_PMU_V2		0b0010
#define ID_DFR0_PMU_V3		0b0011
#define ID_DFR0_PMU_V3_8_1	0b0100
#define ID_DFR0_PMU_V3_8_4	0b0101
#define ID_DFR0_PMU_V3_8_5	0b0110
#define ID_DFR0_PMU_IMPDEF	0b1111

#define PMCR         __ACCESS_CP15(c9, 0, c12, 0)
#define ID_DFR0      __ACCESS_CP15(c0, 0, c1, 2)
#define PMSELR       __ACCESS_CP15(c9, 0, c12, 5)
#define PMXEVTYPER   __ACCESS_CP15(c9, 0, c13, 1)
#define PMCNTENSET   __ACCESS_CP15(c9, 0, c12, 1)
#define PMCNTENCLR   __ACCESS_CP15(c9, 0, c12, 2)
#define PMOVSR       __ACCESS_CP15(c9, 0, c12, 3)
#define PMCCNTR32    __ACCESS_CP15(c9, 0, c13, 0)
#define PMINTENCLR   __ACCESS_CP15(c9, 0, c14, 2)
#define PMCCNTR64    __ACCESS_CP15_64(0, c9)

static inline uint32_t get_id_dfr0(void) { return read_sysreg(ID_DFR0); }
static inline uint32_t get_pmcr(void) { return read_sysreg(PMCR); }
static inline void set_pmcr(uint32_t v) { write_sysreg(v, PMCR); }
static inline void set_pmcntenset(uint32_t v) { write_sysreg(v, PMCNTENSET); }

static inline uint8_t get_pmu_version(void)
{
	return (get_id_dfr0() >> ID_DFR0_PERFMON_SHIFT) & ID_DFR0_PERFMON_MASK;
}

static inline uint64_t get_pmccntr(void)
{
	return read_sysreg(PMCCNTR32);
}

static inline void set_pmccntr(uint64_t value)
{
	write_sysreg(value & 0xffffffff, PMCCNTR32);
}

/* PMCCFILTR is an obsolete name for PMXEVTYPER31 in ARMv7 */
static inline void set_pmccfiltr(uint32_t value)
{
	write_sysreg(PMU_CYCLE_IDX, PMSELR);
	write_sysreg(value, PMXEVTYPER);
	isb();
}

/*
 * Extra instructions inserted by the compiler would be difficult to compensate
 * for, so hand assemble everything between, and including, the PMCR accesses
 * to start and stop counting. isb instructions were inserted to make sure
 * pmccntr read after this function returns the exact instructions executed in
 * the controlled block. Total instrs = isb + mcr + 2*loop = 2 + 2*loop.
 */
static inline void precise_instrs_loop(int loop, uint32_t pmcr)
{
	asm volatile(
	"	mcr	p15, 0, %[pmcr], c9, c12, 0\n"
	"	isb\n"
	"1:	subs	%[loop], %[loop], #1\n"
	"	bgt	1b\n"
	"	mcr	p15, 0, %[z], c9, c12, 0\n"
	"	isb\n"
	: [loop] "+r" (loop)
	: [pmcr] "r" (pmcr), [z] "r" (0)
	: "cc");
}

static void pmu_reset(void)
{
	/* reset all counters, counting disabled at PMCR level*/
	set_pmcr(pmu.pmcr_ro | PMU_PMCR_LC | PMU_PMCR_C | PMU_PMCR_P);
	/* Disable all counters */
	write_sysreg(ALL_SET_32, PMCNTENCLR);
	/* clear overflow reg */
	write_sysreg(ALL_SET_32, PMOVSR);
	/* disable overflow interrupts on all counters */
	write_sysreg(ALL_SET_32, PMINTENCLR);
	isb();
}

/* event counter tests only implemented for aarch64 */
static void test_event_introspection(void) {}
static void test_event_counter_config(void) {}
static void test_basic_event_count(bool overflow_at_64bits) {}
static void test_mem_access_reliability(bool overflow_at_64bits) {}
static void test_mem_access(bool overflow_at_64bits) {}
static void test_sw_incr(bool overflow_at_64bits) {}
static void test_chained_counters(bool unused) {}
static void test_chained_sw_incr(bool unused) {}
static void test_chain_promotion(bool unused) {}
static void test_overflow_interrupt(bool overflow_at_64bits) {}

#elif defined(__aarch64__)
#define ID_AA64DFR0_PERFMON_SHIFT 8
#define ID_AA64DFR0_PERFMON_MASK  0xf

#define ID_DFR0_PMU_NOTIMPL	0b0000
#define ID_DFR0_PMU_V3		0b0001
#define ID_DFR0_PMU_V3_8_1	0b0100
#define ID_DFR0_PMU_V3_8_4	0b0101
#define ID_DFR0_PMU_V3_8_5	0b0110
#define ID_DFR0_PMU_IMPDEF	0b1111

static inline uint32_t get_id_aa64dfr0(void) { return read_sysreg(id_aa64dfr0_el1); }
static inline uint32_t get_pmcr(void) { return read_sysreg(pmcr_el0); }
static inline void set_pmcr(uint32_t v) { write_sysreg(v, pmcr_el0); }
static inline uint64_t get_pmccntr(void) { return read_sysreg(pmccntr_el0); }
static inline void set_pmccntr(uint64_t v) { write_sysreg(v, pmccntr_el0); }
static inline void set_pmcntenset(uint32_t v) { write_sysreg(v, pmcntenset_el0); }
static inline void set_pmccfiltr(uint32_t v) { write_sysreg(v, pmccfiltr_el0); }

static inline uint8_t get_pmu_version(void)
{
	uint8_t ver = (get_id_aa64dfr0() >> ID_AA64DFR0_PERFMON_SHIFT) & ID_AA64DFR0_PERFMON_MASK;
	return ver;
}

/*
 * Extra instructions inserted by the compiler would be difficult to compensate
 * for, so hand assemble everything between, and including, the PMCR accesses
 * to start and stop counting. isb instructions are inserted to make sure
 * pmccntr read after this function returns the exact instructions executed
 * in the controlled block. Total instrs = isb + msr + 2*loop = 2 + 2*loop.
 */
static inline void precise_instrs_loop(int loop, uint32_t pmcr)
{
	uint64_t pmcr64 = pmcr;
	asm volatile(
	"	msr	pmcr_el0, %[pmcr]\n"
	"	isb\n"
	"1:	subs	%w[loop], %w[loop], #1\n"
	"	b.gt	1b\n"
	"	msr	pmcr_el0, xzr\n"
	"	isb\n"
	: [loop] "+r" (loop)
	: [pmcr] "r" (pmcr64)
	: "cc");
}

#define PMCEID1_EL0 sys_reg(3, 3, 9, 12, 7)
#define PMCNTENSET_EL0 sys_reg(3, 3, 9, 12, 1)
#define PMCNTENCLR_EL0 sys_reg(3, 3, 9, 12, 2)

#define PMEVTYPER_EXCLUDE_EL1 BIT(31)
#define PMEVTYPER_EXCLUDE_EL0 BIT(30)

static bool is_event_supported(uint32_t n, bool warn)
{
	uint64_t pmceid0 = read_sysreg(pmceid0_el0);
	uint64_t pmceid1 = read_sysreg_s(PMCEID1_EL0);
	bool supported;
	uint64_t reg;

	/*
	 * The low 32-bits of PMCEID0/1 respectively describe
	 * event support for events 0-31/32-63. Their High
	 * 32-bits describe support for extended events
	 * starting at 0x4000, using the same split.
	 */
	assert((n >= COMMON_EVENTS_LOW  && n <= COMMON_EVENTS_HIGH) ||
	       (n >= EXT_COMMON_EVENTS_LOW && n <= EXT_COMMON_EVENTS_HIGH));

	if (n <= COMMON_EVENTS_HIGH)
		reg = lower_32_bits(pmceid0) | ((u64)lower_32_bits(pmceid1) << 32);
	else
		reg = upper_32_bits(pmceid0) | ((u64)upper_32_bits(pmceid1) << 32);

	supported =  reg & (1UL << (n & 0x3F));

	if (!supported && warn)
		report_info("event 0x%x is not supported", n);
	return supported;
}

static void test_event_introspection(void)
{
	bool required_events;

	if (!pmu.nb_implemented_counters) {
		report_skip("No event counter, skip ...");
		return;
	}

	/* PMUv3 requires an implementation includes some common events */
	required_events = is_event_supported(SW_INCR, true) &&
			  is_event_supported(CPU_CYCLES, true) &&
			  (is_event_supported(INST_RETIRED, true) ||
			   is_event_supported(INST_PREC, true));

	if (pmu.version >= ID_DFR0_PMU_V3_8_1) {
		required_events = required_events &&
				  is_event_supported(STALL_FRONTEND, true) &&
				  is_event_supported(STALL_BACKEND, true);
	}

	report(required_events, "Check required events are implemented");
}

/*
 * Extra instructions inserted by the compiler would be difficult to compensate
 * for, so hand assemble everything between, and including, the PMCR accesses
 * to start and stop counting. isb instructions are inserted to make sure
 * pmccntr read after this function returns the exact instructions executed
 * in the controlled block. Loads @loop times the data at @address into x9.
 */
static void mem_access_loop(void *addr, long loop, uint32_t pmcr)
{
	uint64_t pmcr64 = pmcr;
asm volatile(
	"       dsb     ish\n"
	"       msr     pmcr_el0, %[pmcr]\n"
	"       isb\n"
	"       dsb     ish\n"
	"       mov     x10, %[loop]\n"
	"1:     sub     x10, x10, #1\n"
	"       ldr	x9, [%[addr]]\n"
	"       cmp     x10, #0x0\n"
	"       b.gt    1b\n"
	"       dsb     ish\n"
	"       msr     pmcr_el0, xzr\n"
	"       isb\n"
	:
	: [addr] "r" (addr), [pmcr] "r" (pmcr64), [loop] "r" (loop)
	: "x9", "x10", "cc");
}

static volatile struct pmu_stats pmu_stats;

static void irq_handler(struct pt_regs *regs)
{
	uint32_t irqstat, irqnr;

	irqstat = gic_read_iar();
	irqnr = gic_iar_irqnr(irqstat);

	if (irqnr == PMU_PPI) {
		unsigned long overflows = read_sysreg(pmovsclr_el0);
		int i;

		for (i = 0; i < 32; i++) {
			if (test_and_clear_bit(i, &overflows)) {
				pmu_stats.interrupts[i]++;
				pmu_stats.bitmap |= 1 << i;
			}
		}
		write_sysreg(ALL_SET_32, pmovsclr_el0);
		isb();
	} else {
		pmu_stats.unexpected = true;
	}
	gic_write_eoir(irqstat);
}

static void pmu_reset_stats(void)
{
	int i;

	for (i = 0; i < 32; i++)
		pmu_stats.interrupts[i] = 0;

	pmu_stats.bitmap = 0;
	pmu_stats.unexpected = false;
}

static void pmu_reset(void)
{
	/* reset all counters, counting disabled at PMCR level*/
	set_pmcr(pmu.pmcr_ro | PMU_PMCR_LC | PMU_PMCR_C | PMU_PMCR_P);
	/* Disable all counters */
	write_sysreg_s(ALL_SET_32, PMCNTENCLR_EL0);
	/* clear overflow reg */
	write_sysreg(ALL_SET_32, pmovsclr_el0);
	/* disable overflow interrupts on all counters */
	write_sysreg(ALL_SET_32, pmintenclr_el1);
	pmu_reset_stats();
	isb();
}

static void test_event_counter_config(void)
{
	int i;

	if (!pmu.nb_implemented_counters) {
		report_skip("No event counter, skip ...");
		return;
	}

	pmu_reset();

	/*
	 * Test setting through PMESELR/PMXEVTYPER and PMEVTYPERn read,
	 * select counter 0
	 */
	write_sysreg(1, PMSELR_EL0);
	/* program this counter to count unsupported event */
	write_sysreg(0xEA, PMXEVTYPER_EL0);
	write_sysreg(0xdeadbeef, PMXEVCNTR_EL0);
	report((read_regn_el0(pmevtyper, 1) & 0xFFF) == 0xEA,
		"PMESELR/PMXEVTYPER/PMEVTYPERn");
	report((read_regn_el0(pmevcntr, 1) == 0xdeadbeef),
		"PMESELR/PMXEVCNTR/PMEVCNTRn");

	/* try to configure an unsupported event within the range [0x0, 0x3F] */
	for (i = 0; i <= 0x3F; i++) {
		if (!is_event_supported(i, false))
			break;
	}
	if (i > 0x3F) {
		report_skip("pmevtyper: all events within [0x0, 0x3F] are supported");
		return;
	}

	/* select counter 0 */
	write_sysreg(0, PMSELR_EL0);
	/* program this counter to count unsupported event */
	write_sysreg(i, PMXEVCNTR_EL0);
	/* read the counter value */
	read_sysreg(PMXEVCNTR_EL0);
	report(read_sysreg(PMXEVCNTR_EL0) == i,
		"read of a counter programmed with unsupported event");
}

static bool satisfy_prerequisites(uint32_t *events, unsigned int nb_events)
{
	int i;

	if (pmu.nb_implemented_counters < nb_events) {
		report_skip("Skip test as number of counters is too small (%d)",
			    pmu.nb_implemented_counters);
		return false;
	}

	for (i = 0; i < nb_events; i++) {
		if (!is_event_supported(events[i], false)) {
			report_skip("Skip test as event 0x%x is not supported",
				    events[i]);
			return false;
		}
	}
	return true;
}

static uint64_t pmevcntr_mask(void)
{
	/*
	 * Bits [63:0] are always incremented for 64-bit counters,
	 * even if the PMU is configured to generate an overflow at
	 * bits [31:0]
	 *
	 * For more details see the AArch64.IncrementEventCounter()
	 * pseudo-code in the ARM ARM DDI 0487I.a, section J1.1.1.
	 */
	if (pmu.version >= ID_DFR0_PMU_V3_8_5)
		return ~0;

	return (uint32_t)~0;
}

static bool check_overflow_prerequisites(bool overflow_at_64bits)
{
	if (overflow_at_64bits && pmu.version < ID_DFR0_PMU_V3_8_5) {
		report_skip("Skip test as 64 overflows need FEAT_PMUv3p5");
		return false;
	}

	return true;
}

static void test_basic_event_count(bool overflow_at_64bits)
{
	uint32_t implemented_counter_mask, non_implemented_counter_mask;
	uint64_t pre_overflow = PRE_OVERFLOW(overflow_at_64bits);
	uint64_t pmcr_lp = overflow_at_64bits ? PMU_PMCR_LP : 0;
	uint32_t events[] = {CPU_CYCLES, INST_RETIRED};
	uint32_t counter_mask;

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)) ||
	    !check_overflow_prerequisites(overflow_at_64bits))
		return;

	implemented_counter_mask = BIT(pmu.nb_implemented_counters) - 1;
	non_implemented_counter_mask = ~(BIT(31) | implemented_counter_mask);
	counter_mask = implemented_counter_mask | non_implemented_counter_mask;

	write_regn_el0(pmevtyper, 0, CPU_CYCLES | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, INST_RETIRED | PMEVTYPER_EXCLUDE_EL0);

	/* disable all counters */
	write_sysreg_s(ALL_SET_32, PMCNTENCLR_EL0);
	report(!read_sysreg_s(PMCNTENCLR_EL0) && !read_sysreg_s(PMCNTENSET_EL0),
		"pmcntenclr: disable all counters");

	/*
	 * clear cycle and all event counters and allow counter enablement
	 * through PMCNTENSET. LC is RES1.
	 */
	set_pmcr(pmu.pmcr_ro | PMU_PMCR_LC | PMU_PMCR_C | PMU_PMCR_P | pmcr_lp);
	isb();
	report(get_pmcr() == (pmu.pmcr_ro | PMU_PMCR_LC | pmcr_lp), "pmcr: reset counters");

	/* Preset counter #0 to pre overflow value to trigger an overflow */
	write_regn_el0(pmevcntr, 0, pre_overflow);
	report(read_regn_el0(pmevcntr, 0) == pre_overflow,
		"counter #0 preset to pre-overflow value");
	report(!read_regn_el0(pmevcntr, 1), "counter #1 is 0");

	/*
	 * Enable all implemented counters and also attempt to enable
	 * not supported counters. Counting still is disabled by !PMCR.E
	 */
	write_sysreg_s(counter_mask, PMCNTENSET_EL0);

	/* check only those implemented are enabled */
	report((read_sysreg_s(PMCNTENSET_EL0) == read_sysreg_s(PMCNTENCLR_EL0)) &&
		(read_sysreg_s(PMCNTENSET_EL0) == implemented_counter_mask),
		"pmcntenset: enabled implemented_counters");

	/* Disable all counters but counters #0 and #1 */
	write_sysreg_s(~0x3, PMCNTENCLR_EL0);
	report((read_sysreg_s(PMCNTENSET_EL0) == read_sysreg_s(PMCNTENCLR_EL0)) &&
		(read_sysreg_s(PMCNTENSET_EL0) == 0x3),
		"pmcntenset: just enabled #0 and #1");

	/* clear overflow register */
	write_sysreg(ALL_SET_32, pmovsclr_el0);
	report(!read_sysreg(pmovsclr_el0), "check overflow reg is 0");

	/* disable overflow interrupts on all counters*/
	write_sysreg(ALL_SET_32, pmintenclr_el1);
	report(!read_sysreg(pmintenclr_el1),
		"pmintenclr_el1=0, all interrupts disabled");

	/* enable overflow interrupts on all event counters */
	write_sysreg(implemented_counter_mask | non_implemented_counter_mask,
		     pmintenset_el1);
	report(read_sysreg(pmintenset_el1) == implemented_counter_mask,
		"overflow interrupts enabled on all implemented counters");

	/* Set PMCR.E, execute asm code and unset PMCR.E */
	precise_instrs_loop(20, pmu.pmcr_ro | PMU_PMCR_E);

	report_info("counter #0 is 0x%lx (CPU_CYCLES)",
		    read_regn_el0(pmevcntr, 0));
	report_info("counter #1 is 0x%lx (INST_RETIRED)",
		    read_regn_el0(pmevcntr, 1));

	report_info("overflow reg = 0x%lx", read_sysreg(pmovsclr_el0));
	report(read_sysreg(pmovsclr_el0) == 0x1,
		"check overflow happened on #0 only");
}

static void test_mem_access(bool overflow_at_64bits)
{
	void *addr = malloc(PAGE_SIZE);
	uint32_t events[] = {MEM_ACCESS, MEM_ACCESS};
	uint64_t pre_overflow = PRE_OVERFLOW(overflow_at_64bits);
	uint64_t pmcr_lp = overflow_at_64bits ? PMU_PMCR_LP : 0;

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)) ||
	    !check_overflow_prerequisites(overflow_at_64bits))
		return;

	pmu_reset();

	write_regn_el0(pmevtyper, 0, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	write_sysreg_s(0x3, PMCNTENSET_EL0);
	isb();
	mem_access_loop(addr, 20, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	report_info("counter #0 is 0x%lx (MEM_ACCESS)", read_regn_el0(pmevcntr, 0));
	report_info("counter #1 is 0x%lx (MEM_ACCESS)", read_regn_el0(pmevcntr, 1));
	/* We may measure more than 20 mem access depending on the core */
	report((read_regn_el0(pmevcntr, 0) == read_regn_el0(pmevcntr, 1)) &&
	       (read_regn_el0(pmevcntr, 0) >= 20) && !read_sysreg(pmovsclr_el0),
	       "Ran 20 mem accesses");

	pmu_reset();

	write_regn_el0(pmevcntr, 0, pre_overflow);
	write_regn_el0(pmevcntr, 1, pre_overflow);
	write_sysreg_s(0x3, PMCNTENSET_EL0);
	isb();
	mem_access_loop(addr, 20, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	report(read_sysreg(pmovsclr_el0) == 0x3,
	       "Ran 20 mem accesses with expected overflows on both counters");
	report_info("cnt#0=0x%lx cnt#1=0x%lx overflow=0x%lx",
			read_regn_el0(pmevcntr, 0), read_regn_el0(pmevcntr, 1),
			read_sysreg(pmovsclr_el0));
}

static void test_sw_incr(bool overflow_at_64bits)
{
	uint64_t pre_overflow = PRE_OVERFLOW(overflow_at_64bits);
	uint64_t pmcr_lp = overflow_at_64bits ? PMU_PMCR_LP : 0;
	uint32_t events[] = {SW_INCR, SW_INCR};
	uint64_t cntr0 = (pre_overflow + 100) & pmevcntr_mask();
	int i;

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)) ||
	    !check_overflow_prerequisites(overflow_at_64bits))
		return;

	pmu_reset();

	write_regn_el0(pmevtyper, 0, SW_INCR | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, SW_INCR | PMEVTYPER_EXCLUDE_EL0);
	/* enable counters #0 and #1 */
	write_sysreg_s(0x3, PMCNTENSET_EL0);

	write_regn_el0(pmevcntr, 0, pre_overflow);
	isb();

	for (i = 0; i < 100; i++)
		write_sysreg(0x1, pmswinc_el0);

	isb();
	report_info("SW_INCR counter #0 has value 0x%lx", read_regn_el0(pmevcntr, 0));
	report(read_regn_el0(pmevcntr, 0) == pre_overflow,
		"PWSYNC does not increment if PMCR.E is unset");

	pmu_reset();

	write_regn_el0(pmevcntr, 0, pre_overflow);
	write_sysreg_s(0x3, PMCNTENSET_EL0);
	set_pmcr(pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	isb();

	for (i = 0; i < 100; i++)
		write_sysreg(0x3, pmswinc_el0);

	isb();
	report(read_regn_el0(pmevcntr, 0) == cntr0, "counter #0 after + 100 SW_INCR");
	report(read_regn_el0(pmevcntr, 1) == 100, "counter #1 after + 100 SW_INCR");
	report_info("counter values after 100 SW_INCR #0=0x%lx #1=0x%lx",
		    read_regn_el0(pmevcntr, 0), read_regn_el0(pmevcntr, 1));
	report(read_sysreg(pmovsclr_el0) == 0x1,
		"overflow on counter #0 after 100 SW_INCR");
}

static void enable_chain_counter(int even)
{
	write_sysreg_s(BIT(even + 1), PMCNTENSET_EL0); /* Enable the high counter first */
	isb();
	write_sysreg_s(BIT(even), PMCNTENSET_EL0); /* Enable the low counter */
	isb();
}

static void disable_chain_counter(int even)
{
	write_sysreg_s(BIT(even), PMCNTENCLR_EL0); /* Disable the low counter first*/
	isb();
	write_sysreg_s(BIT(even + 1), PMCNTENCLR_EL0); /* Disable the high counter */
	isb();
}

static void test_chained_counters(bool unused)
{
	uint32_t events[] = {CPU_CYCLES, CHAIN};
	uint64_t all_set = pmevcntr_mask();

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)))
		return;

	pmu_reset();

	write_regn_el0(pmevtyper, 0, CPU_CYCLES | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, CHAIN | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW_32);
	enable_chain_counter(0);

	precise_instrs_loop(22, pmu.pmcr_ro | PMU_PMCR_E);

	report(read_regn_el0(pmevcntr, 1) == 1, "CHAIN counter #1 incremented");
	report(read_sysreg(pmovsclr_el0) == 0x1, "overflow recorded for chained incr #1");

	/* test 64b overflow */

	pmu_reset();

	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW_32);
	write_regn_el0(pmevcntr, 1, 0x1);
	enable_chain_counter(0);
	precise_instrs_loop(22, pmu.pmcr_ro | PMU_PMCR_E);
	report_info("overflow reg = 0x%lx", read_sysreg(pmovsclr_el0));
	report(read_regn_el0(pmevcntr, 1) == 2, "CHAIN counter #1 set to 2");
	report(read_sysreg(pmovsclr_el0) == 0x1, "overflow recorded for chained incr #2");

	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW_32);
	write_regn_el0(pmevcntr, 1, all_set);

	precise_instrs_loop(22, pmu.pmcr_ro | PMU_PMCR_E);
	report_info("overflow reg = 0x%lx", read_sysreg(pmovsclr_el0));
	report(read_regn_el0(pmevcntr, 1) == 0, "CHAIN counter #1 wrapped");
	report(read_sysreg(pmovsclr_el0) == 0x3, "overflow on even and odd counters");
}

static void test_chained_sw_incr(bool unused)
{
	uint32_t events[] = {SW_INCR, CHAIN};
	uint64_t cntr0 = (PRE_OVERFLOW_32 + 100) & pmevcntr_mask();
	uint64_t cntr1 = (ALL_SET_32 + 1) & pmevcntr_mask();
	int i;

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)))
		return;

	pmu_reset();

	write_regn_el0(pmevtyper, 0, SW_INCR | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, CHAIN | PMEVTYPER_EXCLUDE_EL0);
	enable_chain_counter(0);

	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW_32);
	set_pmcr(pmu.pmcr_ro | PMU_PMCR_E);
	isb();

	for (i = 0; i < 100; i++)
		write_sysreg(0x1, pmswinc_el0);

	isb();
	report((read_sysreg(pmovsclr_el0) == 0x1) &&
		(read_regn_el0(pmevcntr, 1) == 1),
		"overflow and chain counter incremented after 100 SW_INCR/CHAIN");
	report_info("overflow=0x%lx, #0=0x%lx #1=0x%lx", read_sysreg(pmovsclr_el0),
		    read_regn_el0(pmevcntr, 0), read_regn_el0(pmevcntr, 1));

	/* 64b SW_INCR and overflow on CHAIN counter*/
	pmu_reset();

	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW_32);
	write_regn_el0(pmevcntr, 1, ALL_SET_32);
	enable_chain_counter(0);
	set_pmcr(pmu.pmcr_ro | PMU_PMCR_E);
	isb();

	for (i = 0; i < 100; i++)
		write_sysreg(0x1, pmswinc_el0);

	isb();
	report((read_sysreg(pmovsclr_el0) == 0x3) &&
	       (read_regn_el0(pmevcntr, 0) == cntr0) &&
	       (read_regn_el0(pmevcntr, 1) == cntr1),
	       "expected overflows and values after 100 SW_INCR/CHAIN");
	report_info("overflow=0x%lx, #0=0x%lx #1=0x%lx", read_sysreg(pmovsclr_el0),
		    read_regn_el0(pmevcntr, 0), read_regn_el0(pmevcntr, 1));
}
#define PRINT_REGS(__s) \
	report_info("%s #1=0x%lx #0=0x%lx overflow=0x%lx", __s, \
		    read_regn_el0(pmevcntr, 1), \
		    read_regn_el0(pmevcntr, 0), \
		    read_sysreg(pmovsclr_el0))

/*
 * This test checks that a mem access loop featuring COUNT accesses
 * does not overflow with an init value of PRE_OVERFLOW2. It also
 * records the min/max access count to see how much the counting
 * is (un)reliable
 */
static void test_mem_access_reliability(bool overflow_at_64bits)
{
	uint32_t events[] = {MEM_ACCESS};
	void *addr = malloc(PAGE_SIZE);
	uint64_t cntr_val, num_events, max = 0, min = pmevcntr_mask();
	uint64_t pre_overflow2 = PRE_OVERFLOW2(overflow_at_64bits);
	uint64_t all_set = ALL_SET(overflow_at_64bits);
	uint64_t pmcr_lp = overflow_at_64bits ? PMU_PMCR_LP : 0;
	bool overflow = false;

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)) ||
	    !check_overflow_prerequisites(overflow_at_64bits))
		return;

	pmu_reset();
	write_regn_el0(pmevtyper, 0, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	for (int i = 0; i < 100; i++) {
		pmu_reset();
		write_regn_el0(pmevcntr, 0, pre_overflow2);
		write_sysreg_s(0x1, PMCNTENSET_EL0);
		isb();
		mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
		cntr_val = read_regn_el0(pmevcntr, 0);
		if (cntr_val >= pre_overflow2) {
			num_events = cntr_val - pre_overflow2;
		} else {
			/* unexpected counter overflow */
			num_events = cntr_val + all_set - pre_overflow2;
			overflow = true;
			report_info("iter=%d num_events=%ld min=%ld max=%ld overflow!!!",
				    i, num_events, min, max);
		}
		/* record extreme value */
		max = MAX(num_events, max);
		min = MIN(num_events, min);
	}
	report_info("overflow=%d min=%ld max=%ld expected=%d acceptable margin=%d",
		    overflow, min, max, COUNT, MARGIN);
	report(!overflow, "mem_access count is reliable");
}

static void test_chain_promotion(bool unused)
{
	uint32_t events[] = {MEM_ACCESS, CHAIN};
	void *addr = malloc(PAGE_SIZE);

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)))
		return;

	/* Only enable CHAIN counter */
	report_prefix_push("subtest1");
	pmu_reset();
	write_regn_el0(pmevtyper, 0, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, CHAIN | PMEVTYPER_EXCLUDE_EL0);
	write_sysreg_s(0x2, PMCNTENSET_EL0);
	isb();

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("post");
	report(!read_regn_el0(pmevcntr, 0),
		"chain counter not counting if even counter is disabled");
	report_prefix_pop();

	/* Only enable even counter */
	report_prefix_push("subtest2");
	pmu_reset();
	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW_32);
	write_sysreg_s(0x1, PMCNTENSET_EL0);
	isb();

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("post");
	report(!read_regn_el0(pmevcntr, 1) && (read_sysreg(pmovsclr_el0) == 0x1),
		"odd counter did not increment on overflow if disabled");
	report_prefix_pop();

	/* 1st COUNT with CHAIN enabled, next COUNT with CHAIN disabled */
	report_prefix_push("subtest3");
	pmu_reset();
	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW2_32);
	enable_chain_counter(0);
	PRINT_REGS("init");

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 1st loop");

	/* disable the CHAIN event */
	disable_chain_counter(0);
	write_sysreg_s(0x1, PMCNTENSET_EL0); /* Enable the low counter */
	isb();
	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 2nd loop");
	report(read_sysreg(pmovsclr_el0) == 0x1,
		"should have triggered an overflow on #0");
	report(!read_regn_el0(pmevcntr, 1),
		"CHAIN counter #1 shouldn't have incremented");
	report_prefix_pop();

	/* 1st COUNT with CHAIN disabled, next COUNT with CHAIN enabled */

	report_prefix_push("subtest4");
	pmu_reset();
	write_sysreg_s(0x1, PMCNTENSET_EL0);
	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW2_32);
	isb();
	PRINT_REGS("init");

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 1st loop");

	/* Disable the low counter first and enable the chain counter */
	write_sysreg_s(0x1, PMCNTENCLR_EL0);
	isb();
	enable_chain_counter(0);

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);

	PRINT_REGS("After 2nd loop");

	report((read_regn_el0(pmevcntr, 1) == 1) &&
		(read_sysreg(pmovsclr_el0) == 0x1),
		"CHAIN counter enabled: CHAIN counter was incremented and overflow");
	report_prefix_pop();

	/* start as MEM_ACCESS/CPU_CYCLES and move to CHAIN/MEM_ACCESS */
	report_prefix_push("subtest5");
	pmu_reset();
	write_regn_el0(pmevtyper, 0, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, CPU_CYCLES | PMEVTYPER_EXCLUDE_EL0);
	write_sysreg_s(0x3, PMCNTENSET_EL0);
	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW2_32);
	isb();
	PRINT_REGS("init");

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 1st loop");

	/* 0 becomes CHAINED */
	write_sysreg_s(0x3, PMCNTENCLR_EL0);
	write_regn_el0(pmevtyper, 1, CHAIN | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevcntr, 1, 0x0);
	enable_chain_counter(0);

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 2nd loop");

	report((read_regn_el0(pmevcntr, 1) == 1) &&
		(read_sysreg(pmovsclr_el0) == 0x1),
		"32b->64b: CHAIN counter incremented and overflow");
	report_prefix_pop();

	/* start as CHAIN/MEM_ACCESS and move to MEM_ACCESS/CPU_CYCLES */
	report_prefix_push("subtest6");
	pmu_reset();
	write_regn_el0(pmevtyper, 0, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, CHAIN | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevcntr, 0, PRE_OVERFLOW2_32);
	enable_chain_counter(0);
	PRINT_REGS("init");

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 1st loop");

	disable_chain_counter(0);
	write_regn_el0(pmevtyper, 1, CPU_CYCLES | PMEVTYPER_EXCLUDE_EL0);
	write_sysreg_s(0x3, PMCNTENSET_EL0);

	mem_access_loop(addr, COUNT, pmu.pmcr_ro | PMU_PMCR_E);
	PRINT_REGS("After 2nd loop");
	report(read_sysreg(pmovsclr_el0) == 1,
		"overflow is expected on counter 0");
	report_prefix_pop();
}

static bool expect_interrupts(uint32_t bitmap)
{
	int i;

	if (pmu_stats.bitmap ^ bitmap || pmu_stats.unexpected)
		return false;

	for (i = 0; i < 32; i++) {
		if (test_and_clear_bit(i, &pmu_stats.bitmap))
			if (pmu_stats.interrupts[i] != 1)
				return false;
	}
	return true;
}

static void test_overflow_interrupt(bool overflow_at_64bits)
{
	uint64_t pre_overflow = PRE_OVERFLOW(overflow_at_64bits);
	uint64_t all_set = pmevcntr_mask();
	uint64_t pmcr_lp = overflow_at_64bits ? PMU_PMCR_LP : 0;
	uint32_t events[] = {MEM_ACCESS, SW_INCR};
	void *addr = malloc(PAGE_SIZE);
	int i;

	if (!satisfy_prerequisites(events, ARRAY_SIZE(events)) ||
	    !check_overflow_prerequisites(overflow_at_64bits))
		return;

	gic_enable_defaults();
	install_irq_handler(EL1H_IRQ, irq_handler);
	local_irq_enable();
	gic_enable_irq(23);

	pmu_reset();

	write_regn_el0(pmevtyper, 0, MEM_ACCESS | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevtyper, 1, SW_INCR | PMEVTYPER_EXCLUDE_EL0);
	write_sysreg_s(0x3, PMCNTENSET_EL0);
	write_regn_el0(pmevcntr, 0, pre_overflow);
	write_regn_el0(pmevcntr, 1, pre_overflow);
	isb();

	/* interrupts are disabled (PMINTENSET_EL1 == 0) */

	mem_access_loop(addr, COUNT_INT, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	report(expect_interrupts(0), "no overflow interrupt after preset");

	set_pmcr(pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	isb();

	for (i = 0; i < 100; i++)
		write_sysreg(0x2, pmswinc_el0);

	isb();
	set_pmcr(pmu.pmcr_ro);
	isb();
	report(expect_interrupts(0), "no overflow interrupt after counting");

	/* enable interrupts (PMINTENSET_EL1 <= ALL_SET_32) */

	pmu_reset_stats();

	write_regn_el0(pmevcntr, 0, pre_overflow);
	write_regn_el0(pmevcntr, 1, pre_overflow);
	write_sysreg(ALL_SET_32, pmovsclr_el0);
	write_sysreg(ALL_SET_32, pmintenset_el1);
	isb();

	mem_access_loop(addr, COUNT_INT, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);

	set_pmcr(pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	isb();

	for (i = 0; i < 100; i++)
		write_sysreg(0x3, pmswinc_el0);

	mem_access_loop(addr, COUNT_INT, pmu.pmcr_ro);
	report_info("overflow=0x%lx", read_sysreg(pmovsclr_el0));
	report(expect_interrupts(0x3),
		"overflow interrupts expected on #0 and #1");

	/*
	 * promote to 64-b:
	 *
	 * This only applies to the !overflow_at_64bits case, as
	 * overflow_at_64bits doesn't implement CHAIN events. The
	 * overflow_at_64bits case just checks that chained counters are
	 * not incremented when PMCR.LP == 1.
	 */

	pmu_reset_stats();

	write_regn_el0(pmevtyper, 1, CHAIN | PMEVTYPER_EXCLUDE_EL0);
	write_regn_el0(pmevcntr, 0, pre_overflow);
	isb();
	mem_access_loop(addr, COUNT_INT, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	report(expect_interrupts(0x1), "expect overflow interrupt");

	/* overflow on odd counter */
	pmu_reset_stats();
	write_regn_el0(pmevcntr, 0, pre_overflow);
	write_regn_el0(pmevcntr, 1, all_set);
	isb();
	mem_access_loop(addr, COUNT_INT, pmu.pmcr_ro | PMU_PMCR_E | pmcr_lp);
	if (overflow_at_64bits) {
		report(expect_interrupts(0x1),
		       "expect overflow interrupt on even counter");
		report(read_regn_el0(pmevcntr, 1) == all_set,
		       "Odd counter did not change");
	} else {
		report(expect_interrupts(0x3),
		       "expect overflow interrupt on even and odd counter");
		report(read_regn_el0(pmevcntr, 1) != all_set,
		       "Odd counter wrapped");
	}
}
#endif

/*
 * Ensure that the cycle counter progresses between back-to-back reads.
 */
static bool check_cycles_increase(void)
{
	bool success = true;

	/* init before event access, this test only cares about cycle count */
	pmu_reset();
	set_pmcntenset(1 << PMU_CYCLE_IDX);
	set_pmccfiltr(0); /* count cycles in EL0, EL1, but not EL2 */

	set_pmcr(get_pmcr() | PMU_PMCR_LC | PMU_PMCR_C | PMU_PMCR_E);
	isb();

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
	isb();

	return success;
}

/*
 * Execute a known number of guest instructions. Only even instruction counts
 * greater than or equal to 4 are supported by the in-line assembly code. The
 * control register (PMCR_EL0) is initialized with the provided value (allowing
 * for example for the cycle counter or event counters to be reset). At the end
 * of the exact instruction loop, zero is written to PMCR_EL0 to disable
 * counting, allowing the cycle counter or event counters to be read at the
 * leisure of the calling code.
 */
static void measure_instrs(int num, uint32_t pmcr)
{
	int loop = (num - 2) / 2;

	assert(num >= 4 && ((num - 2) % 2 == 0));
	precise_instrs_loop(loop, pmcr);
}

/*
 * Measure cycle counts for various known instruction counts. Ensure that the
 * cycle counter progresses (similar to check_cycles_increase() but with more
 * instructions and using reset and stop controls). If supplied a positive,
 * nonzero CPI parameter, it also strictly checks that every measurement matches
 * it. Strict CPI checking is used to test -icount mode.
 */
static bool check_cpi(int cpi)
{
	uint32_t pmcr = get_pmcr() | PMU_PMCR_LC | PMU_PMCR_C | PMU_PMCR_E;

	/* init before event access, this test only cares about cycle count */
	pmu_reset();
	set_pmcntenset(1 << PMU_CYCLE_IDX);
	set_pmccfiltr(0); /* count cycles in EL0, EL1, but not EL2 */

	if (cpi > 0)
		printf("Checking for CPI=%d.\n", cpi);
	printf("instrs : cycles0 cycles1 ...\n");

	for (unsigned int i = 4; i < 300; i += 32) {
		uint64_t avg, sum = 0;

		printf("%4d:", i);
		for (int j = 0; j < NR_SAMPLES; j++) {
			uint64_t cycles;

			set_pmccntr(0);
			measure_instrs(i, pmcr);
			cycles = get_pmccntr();
			printf(" %4"PRId64"", cycles);

			if (!cycles) {
				printf("\ncycles not incrementing!\n");
				return false;
			} else if (cpi > 0 && cycles != i * cpi) {
				printf("\nunexpected cycle count received!\n");
				return false;
			} else if ((cycles >> 32) != 0) {
				/* The cycles taken by the loop above should
				 * fit in 32 bits easily. We check the upper
				 * 32 bits of the cycle counter to make sure
				 * there is no supprise. */
				printf("\ncycle count bigger than 32bit!\n");
				return false;
			}

			sum += cycles;
		}
		avg = sum / NR_SAMPLES;
		printf(" avg=%-4"PRId64" %s=%-3"PRId64"\n", avg,
		       (avg >= i) ? "cpi" : "ipc",
		       (avg >= i) ? avg / i : i / avg);
	}

	return true;
}

static void pmccntr64_test(void)
{
#ifdef __arm__
	if (pmu.version == ID_DFR0_PMU_V3) {
		if (ERRATA(9e3f7a296940)) {
			write_sysreg(0xdead, PMCCNTR64);
			report(read_sysreg(PMCCNTR64) == 0xdead, "pmccntr64");
		} else
			report_skip("Skipping unsafe pmccntr64 test. Set ERRATA_9e3f7a296940=y to enable.");
	}
#endif
}

/* Return FALSE if no PMU found, otherwise return TRUE */
static bool pmu_probe(void)
{
	uint32_t pmcr;
	uint8_t implementer;

	pmu.version = get_pmu_version();
	if (pmu.version == ID_DFR0_PMU_NOTIMPL || pmu.version == ID_DFR0_PMU_IMPDEF)
		return false;

	report_info("PMU version: 0x%x", pmu.version);

	pmcr = get_pmcr();
	implementer = (pmcr >> PMU_PMCR_IMP_SHIFT) & PMU_PMCR_IMP_MASK;
	report_info("PMU implementer/ID code: %#"PRIx32"(\"%c\")/%#"PRIx32,
		    (pmcr >> PMU_PMCR_IMP_SHIFT) & PMU_PMCR_IMP_MASK,
		    implementer ? implementer : ' ',
		    (pmcr >> PMU_PMCR_ID_SHIFT) & PMU_PMCR_ID_MASK);

	/* store read-only and RES0 fields of the PMCR bottom-half*/
	pmu.pmcr_ro = pmcr & 0xFFFFFF00;
	pmu.nb_implemented_counters =
		(pmcr >> PMU_PMCR_N_SHIFT) & PMU_PMCR_N_MASK;
	report_info("Implements %d event counters",
		    pmu.nb_implemented_counters);

	return true;
}

static void run_test(const char *name, const char *prefix,
		     void (*test)(bool), void *arg)
{
	report_prefix_push(name);
	report_prefix_push(prefix);

	test(arg);

	report_prefix_pop();
	report_prefix_pop();
}

static void run_event_test(char *name, void (*test)(bool),
			   bool overflow_at_64bits)
{
	const char *prefix = overflow_at_64bits ? "64-bit overflows"
						: "32-bit overflows";

	run_test(name, prefix, test, (void *)overflow_at_64bits);
}

int main(int argc, char *argv[])
{
	int cpi = 0;

	if (!pmu_probe()) {
		printf("No PMU found, test skipped...\n");
		return report_summary();
	}

	if (argc < 2)
		report_abort("no test specified");

	report_prefix_push("pmu");

	if (strcmp(argv[1], "cycle-counter") == 0) {
		report_prefix_push(argv[1]);
		if (argc > 2)
			cpi = atol(argv[2]);
		report(check_cycles_increase(),
		       "Monotonically increasing cycle count");
		report(check_cpi(cpi), "Cycle/instruction ratio");
		pmccntr64_test();
		report_prefix_pop();
	} else if (strcmp(argv[1], "pmu-event-introspection") == 0) {
		report_prefix_push(argv[1]);
		test_event_introspection();
		report_prefix_pop();
	} else if (strcmp(argv[1], "pmu-event-counter-config") == 0) {
		report_prefix_push(argv[1]);
		test_event_counter_config();
		report_prefix_pop();
	} else if (strcmp(argv[1], "pmu-basic-event-count") == 0) {
		run_event_test(argv[1], test_basic_event_count, false);
		run_event_test(argv[1], test_basic_event_count, true);
	} else if (strcmp(argv[1], "pmu-mem-access-reliability") == 0) {
		run_event_test(argv[1], test_mem_access_reliability, false);
		run_event_test(argv[1], test_mem_access_reliability, true);
	} else if (strcmp(argv[1], "pmu-mem-access") == 0) {
		run_event_test(argv[1], test_mem_access, false);
		run_event_test(argv[1], test_mem_access, true);
	} else if (strcmp(argv[1], "pmu-sw-incr") == 0) {
		run_event_test(argv[1], test_sw_incr, false);
		run_event_test(argv[1], test_sw_incr, true);
	} else if (strcmp(argv[1], "pmu-chained-counters") == 0) {
		run_event_test(argv[1], test_chained_counters, false);
	} else if (strcmp(argv[1], "pmu-chained-sw-incr") == 0) {
		run_event_test(argv[1], test_chained_sw_incr, false);
	} else if (strcmp(argv[1], "pmu-chain-promotion") == 0) {
		run_event_test(argv[1], test_chain_promotion, false);
	} else if (strcmp(argv[1], "pmu-overflow-interrupt") == 0) {
		run_event_test(argv[1], test_overflow_interrupt, false);
		run_event_test(argv[1], test_overflow_interrupt, true);
	} else {
		report_abort("Unknown sub-test '%s'", argv[1]);
	}

	return report_summary();
}
