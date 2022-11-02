
#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/pmu.h"
#include "x86/apic-defs.h"
#include "x86/apic.h"
#include "x86/desc.h"
#include "x86/isr.h"
#include "alloc.h"

#include "libcflat.h"
#include <stdint.h>

#define N 1000000

// These values match the number of instructions and branches in the
// assembly block in check_emulated_instr().
#define EXPECTED_INSTR 17
#define EXPECTED_BRNCH 5

typedef struct {
	uint32_t ctr;
	uint32_t config;
	uint64_t count;
	int idx;
} pmu_counter_t;

struct pmu_event {
	const char *name;
	uint32_t unit_sel;
	int min;
	int max;
} gp_events[] = {
	{"core cycles", 0x003c, 1*N, 50*N},
	{"instructions", 0x00c0, 10*N, 10.2*N},
	{"ref cycles", 0x013c, 1*N, 30*N},
	{"llc references", 0x4f2e, 1, 2*N},
	{"llc misses", 0x412e, 1, 1*N},
	{"branches", 0x00c4, 1*N, 1.1*N},
	{"branch misses", 0x00c5, 0, 0.1*N},
}, fixed_events[] = {
	{"fixed 1", MSR_CORE_PERF_FIXED_CTR0, 10*N, 10.2*N},
	{"fixed 2", MSR_CORE_PERF_FIXED_CTR0 + 1, 1*N, 30*N},
	{"fixed 3", MSR_CORE_PERF_FIXED_CTR0 + 2, 0.1*N, 30*N}
};

char *buf;

static inline void loop(void)
{
	unsigned long tmp, tmp2, tmp3;

	asm volatile("1: mov (%1), %2; add $64, %1; nop; nop; nop; nop; nop; nop; nop; loop 1b"
			: "=c"(tmp), "=r"(tmp2), "=r"(tmp3): "0"(N), "1"(buf));

}

volatile uint64_t irq_received;

static void cnt_overflow(isr_regs_t *regs)
{
	irq_received++;
	apic_write(APIC_EOI, 0);
}

static bool check_irq(void)
{
	int i;
	irq_received = 0;
	irq_enable();
	for (i = 0; i < 100000 && !irq_received; i++)
		asm volatile("pause");
	irq_disable();
	return irq_received;
}

static bool is_gp(pmu_counter_t *evt)
{
	return evt->ctr < MSR_CORE_PERF_FIXED_CTR0 ||
		evt->ctr >= MSR_IA32_PMC0;
}

static int event_to_global_idx(pmu_counter_t *cnt)
{
	return cnt->ctr - (is_gp(cnt) ? pmu.msr_gp_counter_base :
		(MSR_CORE_PERF_FIXED_CTR0 - FIXED_CNT_INDEX));
}

static struct pmu_event* get_counter_event(pmu_counter_t *cnt)
{
	if (is_gp(cnt)) {
		int i;

		for (i = 0; i < sizeof(gp_events)/sizeof(gp_events[0]); i++)
			if (gp_events[i].unit_sel == (cnt->config & 0xffff))
				return &gp_events[i];
	} else
		return &fixed_events[cnt->ctr - MSR_CORE_PERF_FIXED_CTR0];

	return (void*)0;
}

static void global_enable(pmu_counter_t *cnt)
{
	cnt->idx = event_to_global_idx(cnt);

	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, rdmsr(MSR_CORE_PERF_GLOBAL_CTRL) |
			(1ull << cnt->idx));
}

static void global_disable(pmu_counter_t *cnt)
{
	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, rdmsr(MSR_CORE_PERF_GLOBAL_CTRL) &
			~(1ull << cnt->idx));
}

static void __start_event(pmu_counter_t *evt, uint64_t count)
{
    evt->count = count;
    wrmsr(evt->ctr, evt->count);
    if (is_gp(evt)) {
	    wrmsr(MSR_GP_EVENT_SELECTx(event_to_global_idx(evt)),
		  evt->config | EVNTSEL_EN);
    } else {
	    uint32_t ctrl = rdmsr(MSR_CORE_PERF_FIXED_CTR_CTRL);
	    int shift = (evt->ctr - MSR_CORE_PERF_FIXED_CTR0) * 4;
	    uint32_t usrospmi = 0;

	    if (evt->config & EVNTSEL_OS)
		    usrospmi |= (1 << 0);
	    if (evt->config & EVNTSEL_USR)
		    usrospmi |= (1 << 1);
	    if (evt->config & EVNTSEL_INT)
		    usrospmi |= (1 << 3); // PMI on overflow
	    ctrl = (ctrl & ~(0xf << shift)) | (usrospmi << shift);
	    wrmsr(MSR_CORE_PERF_FIXED_CTR_CTRL, ctrl);
    }
    global_enable(evt);
    apic_write(APIC_LVTPC, PMI_VECTOR);
}

static void start_event(pmu_counter_t *evt)
{
	__start_event(evt, 0);
}

static void stop_event(pmu_counter_t *evt)
{
	global_disable(evt);
	if (is_gp(evt)) {
		wrmsr(MSR_GP_EVENT_SELECTx(event_to_global_idx(evt)),
		      evt->config & ~EVNTSEL_EN);
	} else {
		uint32_t ctrl = rdmsr(MSR_CORE_PERF_FIXED_CTR_CTRL);
		int shift = (evt->ctr - MSR_CORE_PERF_FIXED_CTR0) * 4;
		wrmsr(MSR_CORE_PERF_FIXED_CTR_CTRL, ctrl & ~(0xf << shift));
	}
	evt->count = rdmsr(evt->ctr);
}

static noinline void measure_many(pmu_counter_t *evt, int count)
{
	int i;
	for (i = 0; i < count; i++)
		start_event(&evt[i]);
	loop();
	for (i = 0; i < count; i++)
		stop_event(&evt[i]);
}

static void measure_one(pmu_counter_t *evt)
{
	measure_many(evt, 1);
}

static noinline void __measure(pmu_counter_t *evt, uint64_t count)
{
	__start_event(evt, count);
	loop();
	stop_event(evt);
}

static bool verify_event(uint64_t count, struct pmu_event *e)
{
	// printf("%d <= %ld <= %d\n", e->min, count, e->max);
	return count >= e->min  && count <= e->max;

}

static bool verify_counter(pmu_counter_t *cnt)
{
	return verify_event(cnt->count, get_counter_event(cnt));
}

static void check_gp_counter(struct pmu_event *evt)
{
	pmu_counter_t cnt = {
		.config = EVNTSEL_OS | EVNTSEL_USR | evt->unit_sel,
	};
	int i;

	for (i = 0; i < pmu.nr_gp_counters; i++) {
		cnt.ctr = MSR_GP_COUNTERx(i);
		measure_one(&cnt);
		report(verify_event(cnt.count, evt), "%s-%d", evt->name, i);
	}
}

static void check_gp_counters(void)
{
	int i;

	for (i = 0; i < sizeof(gp_events)/sizeof(gp_events[0]); i++)
		if (pmu_gp_counter_is_available(i))
			check_gp_counter(&gp_events[i]);
		else
			printf("GP event '%s' is disabled\n",
					gp_events[i].name);
}

static void check_fixed_counters(void)
{
	pmu_counter_t cnt = {
		.config = EVNTSEL_OS | EVNTSEL_USR,
	};
	int i;

	for (i = 0; i < pmu.nr_fixed_counters; i++) {
		cnt.ctr = fixed_events[i].unit_sel;
		measure_one(&cnt);
		report(verify_event(cnt.count, &fixed_events[i]), "fixed-%d", i);
	}
}

static void check_counters_many(void)
{
	pmu_counter_t cnt[10];
	int i, n;

	for (i = 0, n = 0; n < pmu.nr_gp_counters; i++) {
		if (!pmu_gp_counter_is_available(i))
			continue;

		cnt[n].ctr = MSR_GP_COUNTERx(n);
		cnt[n].config = EVNTSEL_OS | EVNTSEL_USR |
			gp_events[i % ARRAY_SIZE(gp_events)].unit_sel;
		n++;
	}
	for (i = 0; i < pmu.nr_fixed_counters; i++) {
		cnt[n].ctr = fixed_events[i].unit_sel;
		cnt[n].config = EVNTSEL_OS | EVNTSEL_USR;
		n++;
	}

	measure_many(cnt, n);

	for (i = 0; i < n; i++)
		if (!verify_counter(&cnt[i]))
			break;

	report(i == n, "all counters");
}

static uint64_t measure_for_overflow(pmu_counter_t *cnt)
{
	__measure(cnt, 0);
	/*
	 * To generate overflow, i.e. roll over to '0', the initial count just
	 * needs to be preset to the negative expected count.  However, as per
	 * Intel's SDM, the preset count needs to be incremented by 1 to ensure
	 * the overflow interrupt is generated immediately instead of possibly
	 * waiting for the overflow to propagate through the counter.
	 */
	assert(cnt->count > 1);
	return 1 - cnt->count;
}

static void check_counter_overflow(void)
{
	uint64_t overflow_preset;
	int i;
	pmu_counter_t cnt = {
		.ctr = MSR_GP_COUNTERx(0),
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[1].unit_sel /* instructions */,
	};
	overflow_preset = measure_for_overflow(&cnt);

	/* clear status before test */
	wrmsr(MSR_CORE_PERF_GLOBAL_OVF_CTRL, rdmsr(MSR_CORE_PERF_GLOBAL_STATUS));

	report_prefix_push("overflow");

	for (i = 0; i < pmu.nr_gp_counters + 1; i++) {
		uint64_t status;
		int idx;

		cnt.count = overflow_preset;
		if (pmu_use_full_writes())
			cnt.count &= (1ull << pmu.gp_counter_width) - 1;

		if (i == pmu.nr_gp_counters) {
			cnt.ctr = fixed_events[0].unit_sel;
			cnt.count = measure_for_overflow(&cnt);
			cnt.count &= (1ull << pmu.gp_counter_width) - 1;
		} else {
			cnt.ctr = MSR_GP_COUNTERx(i);
		}

		if (i % 2)
			cnt.config |= EVNTSEL_INT;
		else
			cnt.config &= ~EVNTSEL_INT;
		idx = event_to_global_idx(&cnt);
		__measure(&cnt, cnt.count);
		report(cnt.count == 1, "cntr-%d", i);
		status = rdmsr(MSR_CORE_PERF_GLOBAL_STATUS);
		report(status & (1ull << idx), "status-%d", i);
		wrmsr(MSR_CORE_PERF_GLOBAL_OVF_CTRL, status);
		status = rdmsr(MSR_CORE_PERF_GLOBAL_STATUS);
		report(!(status & (1ull << idx)), "status clear-%d", i);
		report(check_irq() == (i % 2), "irq-%d", i);
	}

	report_prefix_pop();
}

static void check_gp_counter_cmask(void)
{
	pmu_counter_t cnt = {
		.ctr = MSR_GP_COUNTERx(0),
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[1].unit_sel /* instructions */,
	};
	cnt.config |= (0x2 << EVNTSEL_CMASK_SHIFT);
	measure_one(&cnt);
	report(cnt.count < gp_events[1].min, "cmask");
}

static void do_rdpmc_fast(void *ptr)
{
	pmu_counter_t *cnt = ptr;
	uint32_t idx = (uint32_t)cnt->idx | (1u << 31);

	if (!is_gp(cnt))
		idx |= 1 << 30;

	cnt->count = rdpmc(idx);
}


static void check_rdpmc(void)
{
	uint64_t val = 0xff0123456789ull;
	bool exc;
	int i;

	report_prefix_push("rdpmc");

	for (i = 0; i < pmu.nr_gp_counters; i++) {
		uint64_t x;
		pmu_counter_t cnt = {
			.ctr = MSR_GP_COUNTERx(i),
			.idx = i
		};

	        /*
	         * Without full-width writes, only the low 32 bits are writable,
	         * and the value is sign-extended.
	         */
		if (pmu.msr_gp_counter_base == MSR_IA32_PERFCTR0)
			x = (uint64_t)(int64_t)(int32_t)val;
		else
			x = (uint64_t)(int64_t)val;

		/* Mask according to the number of supported bits */
		x &= (1ull << pmu.gp_counter_width) - 1;

		wrmsr(MSR_GP_COUNTERx(i), val);
		report(rdpmc(i) == x, "cntr-%d", i);

		exc = test_for_exception(GP_VECTOR, do_rdpmc_fast, &cnt);
		if (exc)
			report_skip("fast-%d", i);
		else
			report(cnt.count == (u32)val, "fast-%d", i);
	}
	for (i = 0; i < pmu.nr_fixed_counters; i++) {
		uint64_t x = val & ((1ull << pmu.fixed_counter_width) - 1);
		pmu_counter_t cnt = {
			.ctr = MSR_CORE_PERF_FIXED_CTR0 + i,
			.idx = i
		};

		wrmsr(MSR_CORE_PERF_FIXED_CTR0 + i, x);
		report(rdpmc(i | (1 << 30)) == x, "fixed cntr-%d", i);

		exc = test_for_exception(GP_VECTOR, do_rdpmc_fast, &cnt);
		if (exc)
			report_skip("fixed fast-%d", i);
		else
			report(cnt.count == (u32)x, "fixed fast-%d", i);
	}

	report_prefix_pop();
}

static void check_running_counter_wrmsr(void)
{
	uint64_t status;
	uint64_t count;
	pmu_counter_t evt = {
		.ctr = MSR_GP_COUNTERx(0),
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[1].unit_sel,
	};

	report_prefix_push("running counter wrmsr");

	start_event(&evt);
	loop();
	wrmsr(MSR_GP_COUNTERx(0), 0);
	stop_event(&evt);
	report(evt.count < gp_events[1].min, "cntr");

	/* clear status before overflow test */
	wrmsr(MSR_CORE_PERF_GLOBAL_OVF_CTRL,
	      rdmsr(MSR_CORE_PERF_GLOBAL_STATUS));

	start_event(&evt);

	count = -1;
	if (pmu_use_full_writes())
		count &= (1ull << pmu.gp_counter_width) - 1;

	wrmsr(MSR_GP_COUNTERx(0), count);

	loop();
	stop_event(&evt);
	status = rdmsr(MSR_CORE_PERF_GLOBAL_STATUS);
	report(status & 1, "status");

	report_prefix_pop();
}

static void check_emulated_instr(void)
{
	uint64_t status, instr_start, brnch_start;
	pmu_counter_t brnch_cnt = {
		.ctr = MSR_GP_COUNTERx(0),
		/* branch instructions */
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[5].unit_sel,
	};
	pmu_counter_t instr_cnt = {
		.ctr = MSR_GP_COUNTERx(1),
		/* instructions */
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[1].unit_sel,
	};
	report_prefix_push("emulated instruction");

	wrmsr(MSR_CORE_PERF_GLOBAL_OVF_CTRL,
	      rdmsr(MSR_CORE_PERF_GLOBAL_STATUS));

	start_event(&brnch_cnt);
	start_event(&instr_cnt);

	brnch_start = -EXPECTED_BRNCH;
	instr_start = -EXPECTED_INSTR;
	wrmsr(MSR_GP_COUNTERx(0), brnch_start);
	wrmsr(MSR_GP_COUNTERx(1), instr_start);
	// KVM_FEP is a magic prefix that forces emulation so
	// 'KVM_FEP "jne label\n"' just counts as a single instruction.
	asm volatile(
		"mov $0x0, %%eax\n"
		"cmp $0x0, %%eax\n"
		KVM_FEP "jne label\n"
		KVM_FEP "jne label\n"
		KVM_FEP "jne label\n"
		KVM_FEP "jne label\n"
		KVM_FEP "jne label\n"
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
		"label:\n"
		:
		:
		: "eax", "ebx", "ecx", "edx");

	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, 0);

	stop_event(&brnch_cnt);
	stop_event(&instr_cnt);

	// Check that the end count - start count is at least the expected
	// number of instructions and branches.
	report(instr_cnt.count - instr_start >= EXPECTED_INSTR,
	       "instruction count");
	report(brnch_cnt.count - brnch_start >= EXPECTED_BRNCH,
	       "branch count");
	// Additionally check that those counters overflowed properly.
	status = rdmsr(MSR_CORE_PERF_GLOBAL_STATUS);
	report(status & 1, "branch counter overflow");
	report(status & 2, "instruction counter overflow");

	report_prefix_pop();
}

static void check_counters(void)
{
	if (is_fep_available())
		check_emulated_instr();

	check_gp_counters();
	check_fixed_counters();
	check_rdpmc();
	check_counters_many();
	check_counter_overflow();
	check_gp_counter_cmask();
	check_running_counter_wrmsr();
}

static void do_unsupported_width_counter_write(void *index)
{
	wrmsr(MSR_IA32_PMC0 + *((int *) index), 0xffffff0123456789ull);
}

static void check_gp_counters_write_width(void)
{
	u64 val_64 = 0xffffff0123456789ull;
	u64 val_32 = val_64 & ((1ull << 32) - 1);
	u64 val_max_width = val_64 & ((1ull << pmu.gp_counter_width) - 1);
	int i;

	/*
	 * MSR_IA32_PERFCTRn supports 64-bit writes,
	 * but only the lowest 32 bits are valid.
	 */
	for (i = 0; i < pmu.nr_gp_counters; i++) {
		wrmsr(MSR_IA32_PERFCTR0 + i, val_32);
		assert(rdmsr(MSR_IA32_PERFCTR0 + i) == val_32);
		assert(rdmsr(MSR_IA32_PMC0 + i) == val_32);

		wrmsr(MSR_IA32_PERFCTR0 + i, val_max_width);
		assert(rdmsr(MSR_IA32_PERFCTR0 + i) == val_32);
		assert(rdmsr(MSR_IA32_PMC0 + i) == val_32);

		wrmsr(MSR_IA32_PERFCTR0 + i, val_64);
		assert(rdmsr(MSR_IA32_PERFCTR0 + i) == val_32);
		assert(rdmsr(MSR_IA32_PMC0 + i) == val_32);
	}

	/*
	 * MSR_IA32_PMCn supports writing values up to GP counter width,
	 * and only the lowest bits of GP counter width are valid.
	 */
	for (i = 0; i < pmu.nr_gp_counters; i++) {
		wrmsr(MSR_IA32_PMC0 + i, val_32);
		assert(rdmsr(MSR_IA32_PMC0 + i) == val_32);
		assert(rdmsr(MSR_IA32_PERFCTR0 + i) == val_32);

		wrmsr(MSR_IA32_PMC0 + i, val_max_width);
		assert(rdmsr(MSR_IA32_PMC0 + i) == val_max_width);
		assert(rdmsr(MSR_IA32_PERFCTR0 + i) == val_max_width);

		report(test_for_exception(GP_VECTOR,
			do_unsupported_width_counter_write, &i),
		"writing unsupported width to MSR_IA32_PMC%d raises #GP", i);
	}
}

/*
 * Per the SDM, reference cycles are currently implemented using the
 * core crystal clock, TSC, or bus clock. Calibrate to the TSC
 * frequency to set reasonable expectations.
 */
static void set_ref_cycle_expectations(void)
{
	pmu_counter_t cnt = {
		.ctr = MSR_IA32_PERFCTR0,
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[2].unit_sel,
	};
	uint64_t tsc_delta;
	uint64_t t0, t1, t2, t3;

	/* Bit 2 enumerates the availability of reference cycles events. */
	if (!pmu.nr_gp_counters || !pmu_gp_counter_is_available(2))
		return;

	wrmsr(MSR_CORE_PERF_GLOBAL_CTRL, 0);

	t0 = fenced_rdtsc();
	start_event(&cnt);
	t1 = fenced_rdtsc();

	/*
	 * This loop has to run long enough to dominate the VM-exit
	 * costs for playing with the PMU MSRs on start and stop.
	 *
	 * On a 2.6GHz Ice Lake, with the TSC frequency at 104 times
	 * the core crystal clock, this function calculated a guest
	 * TSC : ref cycles ratio of around 105 with ECX initialized
	 * to one billion.
	 */
	asm volatile("loop ." : "+c"((int){1000000000ull}));

	t2 = fenced_rdtsc();
	stop_event(&cnt);
	t3 = fenced_rdtsc();

	tsc_delta = ((t2 - t1) + (t3 - t0)) / 2;

	if (!tsc_delta)
		return;

	gp_events[2].min = (gp_events[2].min * cnt.count) / tsc_delta;
	gp_events[2].max = (gp_events[2].max * cnt.count) / tsc_delta;
}

static void check_invalid_rdpmc_gp(void)
{
	uint64_t val;

	report(rdpmc_safe(64, &val) == GP_VECTOR,
	       "Expected #GP on RDPMC(64)");
}

int main(int ac, char **av)
{
	setup_vm();
	handle_irq(PMI_VECTOR, cnt_overflow);
	buf = malloc(N*64);

	check_invalid_rdpmc_gp();

	if (!pmu.version) {
		report_skip("No Intel Arch PMU is detected!");
		return report_summary();
	}

	if (pmu.version == 1) {
		report_skip("PMU version 1 is not supported.");
		return report_summary();
	}

	set_ref_cycle_expectations();

	printf("PMU version:         %d\n", pmu.version);
	printf("GP counters:         %d\n", pmu.nr_gp_counters);
	printf("GP counter width:    %d\n", pmu.gp_counter_width);
	printf("Mask length:         %d\n", pmu.gp_counter_mask_length);
	printf("Fixed counters:      %d\n", pmu.nr_fixed_counters);
	printf("Fixed counter width: %d\n", pmu.fixed_counter_width);

	apic_write(APIC_LVTPC, PMI_VECTOR);

	check_counters();

	if (pmu_has_full_writes()) {
		pmu.msr_gp_counter_base = MSR_IA32_PMC0;

		report_prefix_push("full-width writes");
		check_counters();
		check_gp_counters_write_width();
		report_prefix_pop();
	}

	return report_summary();
}
