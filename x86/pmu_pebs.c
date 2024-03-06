#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/pmu.h"
#include "x86/isr.h"
#include "x86/apic.h"
#include "x86/apic-defs.h"
#include "x86/desc.h"
#include "alloc.h"

#include "vm.h"
#include "processor.h"
#include "vmalloc.h"
#include "alloc_page.h"

/* bits [63:48] provides the size of the current record in bytes */
#define	RECORD_SIZE_OFFSET	48

static unsigned int max_nr_gp_events;
static unsigned long *ds_bufer;
static unsigned long *pebs_buffer;
static u64 ctr_start_val;
static bool has_baseline;

struct debug_store {
	u64	bts_buffer_base;
	u64	bts_index;
	u64	bts_absolute_maximum;
	u64	bts_interrupt_threshold;
	u64	pebs_buffer_base;
	u64	pebs_index;
	u64	pebs_absolute_maximum;
	u64	pebs_interrupt_threshold;
	u64	pebs_event_reset[64];
};

struct pebs_basic {
	u64 format_size;
	u64 ip;
	u64 applicable_counters;
	u64 tsc;
};

struct pebs_meminfo {
	u64 address;
	u64 aux;
	u64 latency;
	u64 tsx_tuning;
};

struct pebs_gprs {
	u64 flags, ip, ax, cx, dx, bx, sp, bp, si, di;
	u64 r8, r9, r10, r11, r12, r13, r14, r15;
};

struct pebs_xmm {
	u64 xmm[16*2];	/* two entries for each register */
};

struct lbr_entry {
	u64 from;
	u64 to;
	u64 info;
};

enum pmc_type {
	GP = 0,
	FIXED,
};

static uint32_t intel_arch_events[] = {
	0x00c4, /* PERF_COUNT_HW_BRANCH_INSTRUCTIONS */
	0x00c5, /* PERF_COUNT_HW_BRANCH_MISSES */
	0x0300, /* PERF_COUNT_HW_REF_CPU_CYCLES */
	0x003c, /* PERF_COUNT_HW_CPU_CYCLES */
	0x00c0, /* PERF_COUNT_HW_INSTRUCTIONS */
	0x013c, /* PERF_COUNT_HW_BUS_CYCLES */
	0x4f2e, /* PERF_COUNT_HW_CACHE_REFERENCES */
	0x412e, /* PERF_COUNT_HW_CACHE_MISSES */
};

/* Iterating each counter value is a waste of time, pick a few typical values. */
static u64 counter_start_values[] = {
	/* if PEBS counter doesn't overflow at all */
	0,
	0xfffffffffff0,
	/* normal counter overflow to have PEBS records */
	0xfffffffffffe,
	/* test whether emulated instructions should trigger PEBS */
	0xffffffffffff,
};

static unsigned int get_adaptive_pebs_record_size(u64 pebs_data_cfg)
{
	unsigned int sz = sizeof(struct pebs_basic);

	if (!has_baseline)
		return sz;

	if (pebs_data_cfg & PEBS_DATACFG_MEMINFO)
		sz += sizeof(struct pebs_meminfo);
	if (pebs_data_cfg & PEBS_DATACFG_GPRS)
		sz += sizeof(struct pebs_gprs);
	if (pebs_data_cfg & PEBS_DATACFG_XMMS)
		sz += sizeof(struct pebs_xmm);
	if (pebs_data_cfg & PEBS_DATACFG_LBRS)
		sz += MAX_NUM_LBR_ENTRY * sizeof(struct lbr_entry);

	return sz;
}

static void cnt_overflow(isr_regs_t *regs)
{
	apic_write(APIC_EOI, 0);
}

static inline void workload(void)
{
	asm volatile(
		"mov $0x0, %%eax\n"
		"cmp $0x0, %%eax\n"
		"jne label2\n"
		"jne label2\n"
		"jne label2\n"
		"jne label2\n"
		"mov $0x0, %%eax\n"
		"cmp $0x0, %%eax\n"
		"jne label2\n"
		"jne label2\n"
		"jne label2\n"
		"jne label2\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"label2:\n"
		:
		:
		: "eax", "ebx", "ecx", "edx");
}

static inline void workload2(void)
{
	asm volatile(
		"mov $0x0, %%eax\n"
		"cmp $0x0, %%eax\n"
		"jne label3\n"
		"jne label3\n"
		"jne label3\n"
		"jne label3\n"
		"mov $0x0, %%eax\n"
		"cmp $0x0, %%eax\n"
		"jne label3\n"
		"jne label3\n"
		"jne label3\n"
		"jne label3\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"mov $0xa, %%eax\n"
		"cpuid\n"
		"label3:\n"
		:
		:
		: "eax", "ebx", "ecx", "edx");
}

static void alloc_buffers(void)
{
	ds_bufer = alloc_page();
	force_4k_page(ds_bufer);
	memset(ds_bufer, 0x0, PAGE_SIZE);

	pebs_buffer = alloc_page();
	force_4k_page(pebs_buffer);
	memset(pebs_buffer, 0x0, PAGE_SIZE);
}

static void free_buffers(void)
{
	if (ds_bufer)
		free_page(ds_bufer);

	if (pebs_buffer)
		free_page(pebs_buffer);
}

static void pebs_enable(u64 bitmask, u64 pebs_data_cfg)
{
	static struct debug_store *ds;
	u64 baseline_extra_ctrl = 0, fixed_ctr_ctrl = 0;
	unsigned int idx;

	if (has_baseline)
		wrmsr(MSR_PEBS_DATA_CFG, pebs_data_cfg);

	ds = (struct debug_store *)ds_bufer;
	ds->pebs_index = ds->pebs_buffer_base = (unsigned long)pebs_buffer;
	ds->pebs_absolute_maximum = (unsigned long)pebs_buffer + PAGE_SIZE;
	ds->pebs_interrupt_threshold = ds->pebs_buffer_base +
		get_adaptive_pebs_record_size(pebs_data_cfg);

	for (idx = 0; idx < pmu.nr_fixed_counters; idx++) {
		if (!(BIT_ULL(FIXED_CNT_INDEX + idx) & bitmask))
			continue;
		if (has_baseline)
			baseline_extra_ctrl = BIT(FIXED_CNT_INDEX + idx * 4);
		wrmsr(MSR_PERF_FIXED_CTRx(idx), ctr_start_val);
		fixed_ctr_ctrl |= (0xbULL << (idx * 4) | baseline_extra_ctrl);
	}
	if (fixed_ctr_ctrl)
		wrmsr(MSR_CORE_PERF_FIXED_CTR_CTRL, fixed_ctr_ctrl);

	for (idx = 0; idx < max_nr_gp_events; idx++) {
		if (!(BIT_ULL(idx) & bitmask))
			continue;
		if (has_baseline)
			baseline_extra_ctrl = ICL_EVENTSEL_ADAPTIVE;
		wrmsr(MSR_GP_EVENT_SELECTx(idx), EVNTSEL_EN | EVNTSEL_OS | EVNTSEL_USR |
						 intel_arch_events[idx] | baseline_extra_ctrl);
		wrmsr(MSR_GP_COUNTERx(idx), ctr_start_val);
	}

	wrmsr(MSR_IA32_DS_AREA,  (unsigned long)ds_bufer);
	wrmsr(MSR_IA32_PEBS_ENABLE, bitmask);
	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, bitmask);
}

static void reset_pebs(void)
{
	memset(ds_bufer, 0x0, PAGE_SIZE);
	memset(pebs_buffer, 0x0, PAGE_SIZE);
	wrmsr(MSR_IA32_PEBS_ENABLE, 0);
	wrmsr(MSR_IA32_DS_AREA,  0);
	if (has_baseline)
		wrmsr(MSR_PEBS_DATA_CFG, 0);

	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, 0);
	wrmsr(MSR_CORE_PERF_GLOBAL_OVF_CTRL, rdmsr(MSR_CORE_PERF_GLOBAL_STATUS));

	pmu_reset_all_counters();
}

static void pebs_disable(unsigned int idx)
{
	/*
	* If we only clear the PEBS_ENABLE bit, the counter will continue to increment.
	* In this very tiny time window, if the counter overflows no pebs record will be generated,
	* but a normal counter irq. Test this fully with two ways.
	*/
	if (idx % 2)
		wrmsr(MSR_IA32_PEBS_ENABLE, 0);

	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, 0);
}

static void check_pebs_records(u64 bitmask, u64 pebs_data_cfg)
{
	struct pebs_basic *pebs_rec = (struct pebs_basic *)pebs_buffer;
	struct debug_store *ds = (struct debug_store *)ds_bufer;
	unsigned int pebs_record_size = get_adaptive_pebs_record_size(pebs_data_cfg);
	unsigned int count = 0;
	bool expected, pebs_idx_match, pebs_size_match, data_cfg_match;
	void *cur_record;

	expected = (ds->pebs_index == ds->pebs_buffer_base) && !pebs_rec->format_size;
	if (!(rdmsr(MSR_CORE_PERF_GLOBAL_STATUS) & GLOBAL_STATUS_BUFFER_OVF)) {
		report(expected, "No OVF irq, none PEBS records.");
		return;
	}

	if (expected) {
		report(!expected, "A OVF irq, but none PEBS records.");
		return;
	}

	expected = ds->pebs_index >= ds->pebs_interrupt_threshold;
	cur_record = (void *)pebs_buffer;
	do {
		pebs_rec = (struct pebs_basic *)cur_record;
		pebs_record_size = pebs_rec->format_size >> RECORD_SIZE_OFFSET;
		pebs_idx_match =
			pebs_rec->applicable_counters & bitmask;
		pebs_size_match =
			pebs_record_size == get_adaptive_pebs_record_size(pebs_data_cfg);
		data_cfg_match =
			(pebs_rec->format_size & GENMASK_ULL(47, 0)) == pebs_data_cfg;
		expected = pebs_idx_match && pebs_size_match && data_cfg_match;
		report(expected,
		       "PEBS record (written seq %d) is verified (including size, counters and cfg).", count);
		cur_record = cur_record + pebs_record_size;
		count++;
	} while (expected && (void *)cur_record < (void *)ds->pebs_index);

	if (!expected) {
		if (!pebs_idx_match)
			printf("FAIL: The applicable_counters (0x%lx) doesn't match with pmc_bitmask (0x%lx).\n",
			       pebs_rec->applicable_counters, bitmask);
		if (!pebs_size_match)
			printf("FAIL: The pebs_record_size (%d) doesn't match with MSR_PEBS_DATA_CFG (%d).\n",
			       pebs_record_size, get_adaptive_pebs_record_size(pebs_data_cfg));
		if (!data_cfg_match)
			printf("FAIL: The pebs_data_cfg (0x%lx) doesn't match with MSR_PEBS_DATA_CFG (0x%lx).\n",
			       pebs_rec->format_size & 0xffffffffffff, pebs_data_cfg);
	}
}

static void check_one_counter(enum pmc_type type,
			      unsigned int idx, u64 pebs_data_cfg)
{
	int pebs_bit = BIT_ULL(type == FIXED ? FIXED_CNT_INDEX + idx : idx);

	report_prefix_pushf("%s counter %d (0x%lx)",
			    type == FIXED ? "Extended Fixed" : "GP", idx, ctr_start_val);
	reset_pebs();
	pebs_enable(pebs_bit, pebs_data_cfg);
	workload();
	pebs_disable(idx);
	check_pebs_records(pebs_bit, pebs_data_cfg);
	report_prefix_pop();
}

/* more than one PEBS records will be generated. */
static void check_multiple_counters(u64 bitmask, u64 pebs_data_cfg)
{
	reset_pebs();
	pebs_enable(bitmask, pebs_data_cfg);
	workload2();
	pebs_disable(0);
	check_pebs_records(bitmask, pebs_data_cfg);
}

static void check_pebs_counters(u64 pebs_data_cfg)
{
	unsigned int idx;
	u64 bitmask = 0;

	for (idx = 0; has_baseline && idx < pmu.nr_fixed_counters; idx++)
		check_one_counter(FIXED, idx, pebs_data_cfg);

	for (idx = 0; idx < max_nr_gp_events; idx++)
		check_one_counter(GP, idx, pebs_data_cfg);

	for (idx = 0; has_baseline && idx < pmu.nr_fixed_counters; idx++)
		bitmask |= BIT_ULL(FIXED_CNT_INDEX + idx);
	for (idx = 0; idx < max_nr_gp_events; idx += 2)
		bitmask |= BIT_ULL(idx);
	report_prefix_pushf("Multiple (0x%lx)", bitmask);
	check_multiple_counters(bitmask, pebs_data_cfg);
	report_prefix_pop();
}

/*
 * Known reasons for none PEBS records:
 *	1. The selected event does not support PEBS;
 *	2. From a core pmu perspective, the vCPU and pCPU models are not same;
 * 	3. Guest counter has not yet overflowed or been cross-mapped by the host;
 */
int main(int ac, char **av)
{
	unsigned int i, j;

	setup_vm();

	max_nr_gp_events = MIN(pmu.nr_gp_counters, ARRAY_SIZE(intel_arch_events));

	printf("PMU version: %d\n", pmu.version);

	has_baseline = pmu_has_pebs_baseline();
	if (pmu_has_full_writes())
		pmu_activate_full_writes();

	if (!pmu.is_intel) {
		report_skip("PEBS requires Intel ICX or later, non-Intel detected");
		return report_summary();
	} else if (!pmu_has_pebs()) {
		report_skip("PEBS required PMU version 2, reported version is %d", pmu.version);
		return report_summary();
	} else if (!pmu_pebs_format()) {
		report_skip("PEBS not enumerated in PERF_CAPABILITIES");
		return report_summary();
	} else if (rdmsr(MSR_IA32_MISC_ENABLE) & MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL) {
		report_skip("PEBS unavailable according to MISC_ENABLE");
		return report_summary();
	}

	printf("PEBS format: %d\n", pmu_pebs_format());
	printf("PEBS GP counters: %d\n", pmu.nr_gp_counters);
	printf("PEBS Fixed counters: %d\n", pmu.nr_fixed_counters);
	printf("PEBS baseline (Adaptive PEBS): %d\n", has_baseline);

	handle_irq(PMI_VECTOR, cnt_overflow);
	alloc_buffers();

	for (i = 0; i < ARRAY_SIZE(counter_start_values); i++) {
		ctr_start_val = counter_start_values[i];
		check_pebs_counters(0);
		if (!has_baseline)
			continue;

		for (j = 0; j <= PEBS_DATACFG_MASK; j++) {
			u64 pebs_data_cfg = j;

			if (pebs_data_cfg & PEBS_DATACFG_LBRS)
				pebs_data_cfg |= ((MAX_NUM_LBR_ENTRY -1) << PEBS_DATACFG_LBR_SHIFT);

			report_prefix_pushf("Adaptive (0x%lx)", pebs_data_cfg);
			check_pebs_counters(pebs_data_cfg);
			report_prefix_pop();
		}
	}

	free_buffers();

	return report_summary();
}
