
#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/pmu.h"
#include "x86/apic-defs.h"
#include "x86/apic.h"
#include "x86/desc.h"
#include "x86/isr.h"
#include "vmalloc.h"
#include "alloc.h"

#include "libcflat.h"
#include <stdint.h>

#define N 1000000

#define IBPB_JMP_INSNS		9
#define IBPB_JMP_BRANCHES	2

#if defined(__i386__) || defined(_M_IX86) /* i386 */
#define IBPB_JMP_ASM(_wrmsr)				\
	"mov $1, %%eax; xor %%edx, %%edx;\n\t"		\
	"mov $73, %%ecx;\n\t"				\
	_wrmsr "\n\t"					\
	"call 1f\n\t"					\
	"1: pop %%eax\n\t"				\
	"add $(2f-1b), %%eax\n\t"			\
	"jmp *%%eax;\n\t"                               \
	"nop;\n\t"					\
	"2: nop;\n\t"
#else /* x86_64 */
#define IBPB_JMP_ASM(_wrmsr)				\
	"mov $1, %%eax; xor %%edx, %%edx;\n\t"		\
	"mov $73, %%ecx;\n\t"				\
	_wrmsr "\n\t"					\
	"call 1f\n\t"					\
	"1: pop %%rax\n\t"				\
	"add $(2f-1b), %%rax\n\t"                       \
	"jmp *%%rax;\n\t"                               \
	"nop;\n\t"					\
	"2: nop;\n\t"
#endif

/* GLOBAL_CTRL enable + disable + clflush/mfence + IBPB_JMP */
#define EXTRA_INSNS  (3 + 3 + 2 + IBPB_JMP_INSNS)
#define LOOP_INSNS   (N * 10 + EXTRA_INSNS)
#define LOOP_BRANCHES  (N + IBPB_JMP_BRANCHES)
#define LOOP_ASM(_wrmsr1, _clflush, _wrmsr2)				\
	_wrmsr1 "\n\t"							\
	"mov %%ecx, %%edi; mov %%ebx, %%ecx;\n\t"			\
	_clflush "\n\t"                                 		\
	"mfence;\n\t"                                   		\
	"1: mov (%1), %2; add $64, %1;\n\t"				\
	"nop; nop; nop; nop; nop; nop; nop;\n\t"			\
	"loop 1b;\n\t"							\
	IBPB_JMP_ASM(_wrmsr2) 						\
	"mov %%edi, %%ecx; xor %%eax, %%eax; xor %%edx, %%edx;\n\t"	\
	_wrmsr1 "\n\t"

#define _loop_asm(_wrmsr1, _clflush, _wrmsr2)			\
do {								\
	asm volatile(LOOP_ASM(_wrmsr1, _clflush, _wrmsr2)	\
		     : "=b"(tmp), "=r"(tmp2), "=r"(tmp3)	\
		     : "a"(eax), "d"(edx), "c"(global_ctl),	\
		       "0"(N), "1"(buf)				\
		     : "edi");					\
} while (0)

/* the number of instructions and branches of the kvm_fep_asm() blob */
#define KVM_FEP_INSNS		22
#define KVM_FEP_BRANCHES	5

/*
 * KVM_FEP is a magic prefix that forces emulation so
 * 'KVM_FEP "jne label\n"' just counts as a single instruction.
 */
#define kvm_fep_asm(_wrmsr)			\
do {						\
	asm volatile(				\
		_wrmsr "\n\t"			\
		"mov %%ecx, %%edi;\n\t"		\
		"mov $0x0, %%eax;\n\t"		\
		"cmp $0x0, %%eax;\n\t"		\
		KVM_FEP "jne 1f\n\t"		\
		KVM_FEP "jne 1f\n\t"		\
		KVM_FEP "jne 1f\n\t"		\
		KVM_FEP "jne 1f\n\t"		\
		KVM_FEP "jne 1f\n\t"		\
		"mov $0xa, %%eax; cpuid;\n\t"	\
		"mov $0xa, %%eax; cpuid;\n\t"	\
		"mov $0xa, %%eax; cpuid;\n\t"	\
		"mov $0xa, %%eax; cpuid;\n\t"	\
		"mov $0xa, %%eax; cpuid;\n\t"	\
		"1: mov %%edi, %%ecx; \n\t"	\
		"xor %%eax, %%eax; \n\t"	\
		"xor %%edx, %%edx;\n\t"		\
		_wrmsr "\n\t"			\
		:				\
		: "a"(eax), "d"(edx), "c"(ecx)	\
		: "ebx", "edi");		\
} while (0)

typedef struct {
	uint32_t ctr;
	uint32_t idx;
	uint64_t config;
	uint64_t count;
} pmu_counter_t;

struct pmu_event {
	const char *name;
	uint32_t unit_sel;
	int min;
	int max;
} intel_gp_events[] = {
	{"core cycles", 0x003c, 1*N, 50*N},
	{"instructions", 0x00c0, 10*N, 10.2*N},
	{"ref cycles", 0x013c, 1*N, 30*N},
	{"llc references", 0x4f2e, 1, 2*N},
	{"llc misses", 0x412e, 1, 1*N},
	{"branches", 0x00c4, 1*N, 1.1*N},
	{"branch misses", 0x00c5, 1, 0.1*N},
}, amd_gp_events[] = {
	{"core cycles", 0x0076, 1*N, 50*N},
	{"instructions", 0x00c0, 10*N, 10.2*N},
	{"branches", 0x00c2, 1*N, 1.1*N},
	{"branch misses", 0x00c3, 1, 0.1*N},
}, fixed_events[] = {
	{"fixed 0", MSR_CORE_PERF_FIXED_CTR0, 10*N, 10.2*N},
	{"fixed 1", MSR_CORE_PERF_FIXED_CTR0 + 1, 1*N, 30*N},
	{"fixed 2", MSR_CORE_PERF_FIXED_CTR0 + 2, 0.1*N, 30*N}
};

/*
 * Events index in intel_gp_events[], ensure consistent with
 * intel_gp_events[].
 */
enum {
	INTEL_INSTRUCTIONS_IDX  = 1,
	INTEL_REF_CYCLES_IDX	= 2,
	INTEL_LLC_MISSES_IDX	= 4,
	INTEL_BRANCHES_IDX	= 5,
	INTEL_BRANCH_MISS_IDX	= 6,
};

/*
 * Events index in amd_gp_events[], ensure consistent with
 * amd_gp_events[].
 */
enum {
	AMD_INSTRUCTIONS_IDX    = 1,
	AMD_BRANCHES_IDX	= 2,
	AMD_BRANCH_MISS_IDX	= 3,
};

char *buf;

static struct pmu_event *gp_events;
static unsigned int gp_events_size;
static unsigned int fixed_counters_num;

static int has_ibpb(void)
{
	return this_cpu_has(X86_FEATURE_SPEC_CTRL) ||
	       this_cpu_has(X86_FEATURE_AMD_IBPB);
}

static inline void __loop(void)
{
	unsigned long tmp, tmp2, tmp3;
	u32 global_ctl = 0;
	u32 eax = 0;
	u32 edx = 0;

	if (this_cpu_has(X86_FEATURE_CLFLUSH) && has_ibpb())
		_loop_asm("nop", "clflush (%1)", "wrmsr");
	else if (this_cpu_has(X86_FEATURE_CLFLUSH))
		_loop_asm("nop", "clflush (%1)", "nop");
	else if (has_ibpb())
		_loop_asm("nop", "nop", "wrmsr");
	else
		_loop_asm("nop", "nop", "nop");
}

/*
 * Enable and disable counters in a whole asm blob to ensure
 * no other instructions are counted in the window between
 * counters enabling and really LOOP_ASM code executing.
 * Thus counters can verify instructions and branches events
 * against precise counts instead of a rough valid count range.
 */
static inline void __precise_loop(u64 cntrs)
{
	unsigned long tmp, tmp2, tmp3;
	u32 global_ctl = pmu.msr_global_ctl;
	u32 eax = cntrs & (BIT_ULL(32) - 1);
	u32 edx = cntrs >> 32;

	if (this_cpu_has(X86_FEATURE_CLFLUSH) && has_ibpb())
		_loop_asm("wrmsr", "clflush (%1)", "wrmsr");
	else if (this_cpu_has(X86_FEATURE_CLFLUSH))
		_loop_asm("wrmsr", "clflush (%1)", "nop");
	else if (has_ibpb())
		_loop_asm("wrmsr", "nop", "wrmsr");
	else
		_loop_asm("wrmsr", "nop", "nop");
}

static inline void loop(u64 cntrs)
{
	if (!this_cpu_has_perf_global_ctrl())
		__loop();
	else
		__precise_loop(cntrs);
}

static void adjust_events_range(struct pmu_event *gp_events,
				int instruction_idx, int branch_idx,
				int branch_miss_idx)
{
	/*
	 * If HW supports GLOBAL_CTRL MSR, enabling and disabling PMCs are
	 * moved in __precise_loop(). Thus, instructions and branches events
	 * can be verified against a precise count instead of a rough range.
	 *
	 * Skip the precise checks on AMD, as AMD CPUs count VMRUN as a branch
	 * instruction in guest context, which* leads to intermittent failures
	 * as the counts will vary depending on how many asynchronous VM-Exits
	 * occur while running the measured code, e.g. if the host takes IRQs.
	 */
	if (pmu.is_intel && this_cpu_has_perf_global_ctrl()) {
		gp_events[instruction_idx].min = LOOP_INSNS;
		gp_events[instruction_idx].max = LOOP_INSNS;
		gp_events[branch_idx].min = LOOP_BRANCHES;
		gp_events[branch_idx].max = LOOP_BRANCHES;
	}

	/*
	 * For CPUs without IBPB support, no way to force to trigger a branch
	 * miss and the measured branch misses is possible to be 0.  Thus
	 * overwrite the lower boundary of branch misses event to 0 to avoid
	 * false positive.
	 */
	if (!has_ibpb())
		gp_events[branch_miss_idx].min = 0;
}

volatile uint64_t irq_received;

static void cnt_overflow(isr_regs_t *regs)
{
	irq_received++;
	apic_write(APIC_LVTPC, apic_read(APIC_LVTPC) & ~APIC_LVT_MASKED);
	apic_write(APIC_EOI, 0);
}

static bool check_irq(void)
{
	int i;
	irq_received = 0;
	sti();
	for (i = 0; i < 100000 && !irq_received; i++)
		asm volatile("pause");
	cli();
	return irq_received;
}

static bool is_gp(pmu_counter_t *evt)
{
	if (!pmu.is_intel)
		return true;

	return evt->ctr < MSR_CORE_PERF_FIXED_CTR0 ||
		evt->ctr >= MSR_IA32_PMC0;
}

static int event_to_global_idx(pmu_counter_t *cnt)
{
	if (pmu.is_intel)
		return cnt->ctr - (is_gp(cnt) ? pmu.msr_gp_counter_base :
			(MSR_CORE_PERF_FIXED_CTR0 - FIXED_CNT_INDEX));

	if (pmu.msr_gp_counter_base == MSR_F15H_PERF_CTR0)
		return (cnt->ctr - pmu.msr_gp_counter_base) / 2;
	else
		return cnt->ctr - pmu.msr_gp_counter_base;
}

static struct pmu_event* get_counter_event(pmu_counter_t *cnt)
{
	if (is_gp(cnt)) {
		int i;

		for (i = 0; i < gp_events_size; i++)
			if (gp_events[i].unit_sel == (cnt->config & 0xffff))
				return &gp_events[i];
	} else {
		unsigned int idx = cnt->ctr - MSR_CORE_PERF_FIXED_CTR0;

		if (idx < ARRAY_SIZE(fixed_events))
			return &fixed_events[idx];
	}

	return (void*)0;
}

static void global_enable(pmu_counter_t *cnt)
{
	if (!this_cpu_has_perf_global_ctrl())
		return;

	cnt->idx = event_to_global_idx(cnt);
	wrmsr(pmu.msr_global_ctl, rdmsr(pmu.msr_global_ctl) | BIT_ULL(cnt->idx));
}

static void global_disable(pmu_counter_t *cnt)
{
	if (!this_cpu_has_perf_global_ctrl())
		return;

	wrmsr(pmu.msr_global_ctl, rdmsr(pmu.msr_global_ctl) & ~BIT_ULL(cnt->idx));
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
    apic_write(APIC_LVTPC, PMI_VECTOR);
}

static void start_event(pmu_counter_t *evt)
{
	__start_event(evt, 0);
	global_enable(evt);
}

static void __stop_event(pmu_counter_t *evt)
{
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

static void stop_event(pmu_counter_t *evt)
{
	global_disable(evt);
	__stop_event(evt);
}

static noinline void measure_many(pmu_counter_t *evt, int count)
{
	int i;
	u64 cntrs = 0;

	for (i = 0; i < count; i++) {
		__start_event(&evt[i], 0);
		cntrs |= BIT_ULL(event_to_global_idx(&evt[i]));
	}
	loop(cntrs);
	for (i = 0; i < count; i++)
		__stop_event(&evt[i]);
}

static void measure_one(pmu_counter_t *evt)
{
	measure_many(evt, 1);
}

static noinline void __measure(pmu_counter_t *evt, uint64_t count)
{
	u64 cntrs = BIT_ULL(event_to_global_idx(evt));

	__start_event(evt, count);
	loop(cntrs);
	__stop_event(evt);
}

static bool verify_event(uint64_t count, struct pmu_event *e)
{
	bool pass;

	if (!e)
		return false;

	pass = count >= e->min && count <= e->max;
	if (!pass)
		printf("FAIL: %d <= %"PRId64" <= %d\n", e->min, count, e->max);

	return pass;
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

	for (i = 0; i < gp_events_size; i++)
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

	for (i = 0; i < fixed_counters_num; i++) {
		cnt.ctr = fixed_events[i].unit_sel;
		measure_one(&cnt);
		report(verify_event(cnt.count, &fixed_events[i]), "fixed-%d", i);
	}
}

static void check_counters_many(void)
{
	pmu_counter_t cnt[48];
	int i, n;

	for (i = 0, n = 0; n < pmu.nr_gp_counters; i++) {
		if (!pmu_gp_counter_is_available(i))
			continue;

		cnt[n].ctr = MSR_GP_COUNTERx(n);
		cnt[n].config = EVNTSEL_OS | EVNTSEL_USR |
			gp_events[i % gp_events_size].unit_sel;
		n++;
	}
	for (i = 0; i < fixed_counters_num; i++) {
		cnt[n].ctr = fixed_events[i].unit_sel;
		cnt[n].config = EVNTSEL_OS | EVNTSEL_USR;
		n++;
	}

	assert(n <= ARRAY_SIZE(cnt));
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
	int i;
	uint64_t overflow_preset;
	int instruction_idx = pmu.is_intel ?
			      INTEL_INSTRUCTIONS_IDX :
			      AMD_INSTRUCTIONS_IDX;

	pmu_counter_t cnt = {
		.ctr = MSR_GP_COUNTERx(0),
		.config = EVNTSEL_OS | EVNTSEL_USR |
			  gp_events[instruction_idx].unit_sel /* instructions */,
	};
	overflow_preset = measure_for_overflow(&cnt);

	/* clear status before test */
	if (this_cpu_has_perf_global_status())
		pmu_clear_global_status();

	report_prefix_push("overflow");

	for (i = 0; i < pmu.nr_gp_counters + 1; i++) {
		uint64_t status;
		int idx;

		cnt.count = overflow_preset;
		if (pmu_use_full_writes())
			cnt.count &= (1ull << pmu.gp_counter_width) - 1;

		if (i == pmu.nr_gp_counters) {
			if (!pmu.is_intel)
				break;

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
		if (pmu.is_intel)
			report(cnt.count == 1, "cntr-%d", i);
		else
			report(cnt.count == 0xffffffffffff || cnt.count < 7, "cntr-%d", i);

		if (!this_cpu_has_perf_global_status())
			continue;

		status = rdmsr(pmu.msr_global_status);
		report(status & (1ull << idx), "status-%d", i);
		wrmsr(pmu.msr_global_status_clr, status);
		status = rdmsr(pmu.msr_global_status);
		report(!(status & (1ull << idx)), "status clear-%d", i);
		report(check_irq() == (i % 2), "irq-%d", i);
	}

	report_prefix_pop();
}

static void check_gp_counter_cmask(void)
{
	int instruction_idx = pmu.is_intel ?
			      INTEL_INSTRUCTIONS_IDX :
			      AMD_INSTRUCTIONS_IDX;

	pmu_counter_t cnt = {
		.ctr = MSR_GP_COUNTERx(0),
		.config = EVNTSEL_OS | EVNTSEL_USR |
			  gp_events[instruction_idx].unit_sel /* instructions */,
	};
	cnt.config |= (0x2 << EVNTSEL_CMASK_SHIFT);
	measure_one(&cnt);
	report(cnt.count < gp_events[instruction_idx].min, "cmask");
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
	for (i = 0; i < fixed_counters_num; i++) {
		uint64_t x = val & ((1ull << pmu.fixed_counter_width) - 1);
		pmu_counter_t cnt = {
			.ctr = MSR_CORE_PERF_FIXED_CTR0 + i,
			.idx = i
		};

		wrmsr(MSR_PERF_FIXED_CTRx(i), x);
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
	unsigned int instruction_idx = pmu.is_intel ?
				       INTEL_INSTRUCTIONS_IDX :
				       AMD_INSTRUCTIONS_IDX;

	pmu_counter_t evt = {
		.ctr = MSR_GP_COUNTERx(0),
		.config = EVNTSEL_OS | EVNTSEL_USR |
			  gp_events[instruction_idx].unit_sel,
	};

	report_prefix_push("running counter wrmsr");

	start_event(&evt);
	__loop();
	wrmsr(MSR_GP_COUNTERx(0), 0);
	stop_event(&evt);
	report(evt.count < gp_events[instruction_idx].min, "cntr");

	/* clear status before overflow test */
	if (this_cpu_has_perf_global_status())
		pmu_clear_global_status();

	start_event(&evt);

	count = -1;
	if (pmu_use_full_writes())
		count &= (1ull << pmu.gp_counter_width) - 1;

	wrmsr(MSR_GP_COUNTERx(0), count);

	__loop();
	stop_event(&evt);

	if (this_cpu_has_perf_global_status()) {
		status = rdmsr(pmu.msr_global_status);
		report(status & 1, "status msr bit");
	}

	report_prefix_pop();
}

static void check_emulated_instr(void)
{
	u32 eax, edx, ecx;
	uint64_t status, instr_start, brnch_start;
	uint64_t gp_counter_width = (1ull << pmu.gp_counter_width) - 1;
	unsigned int branch_idx = pmu.is_intel ?
				  INTEL_BRANCHES_IDX : AMD_BRANCHES_IDX;
	unsigned int instruction_idx = pmu.is_intel ?
				       INTEL_INSTRUCTIONS_IDX :
				       AMD_INSTRUCTIONS_IDX;

	pmu_counter_t brnch_cnt = {
		.ctr = MSR_GP_COUNTERx(0),
		/* branch instructions */
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[branch_idx].unit_sel,
	};
	pmu_counter_t instr_cnt = {
		.ctr = MSR_GP_COUNTERx(1),
		/* instructions */
		.config = EVNTSEL_OS | EVNTSEL_USR | gp_events[instruction_idx].unit_sel,
	};
	report_prefix_push("emulated instruction");

	if (this_cpu_has_perf_global_status())
		pmu_clear_global_status();

	__start_event(&brnch_cnt, 0);
	__start_event(&instr_cnt, 0);

	brnch_start = -KVM_FEP_BRANCHES;
	instr_start = -KVM_FEP_INSNS;
	wrmsr(MSR_GP_COUNTERx(0), brnch_start & gp_counter_width);
	wrmsr(MSR_GP_COUNTERx(1), instr_start & gp_counter_width);

	if (this_cpu_has_perf_global_ctrl()) {
		eax = BIT(0) | BIT(1);
		ecx = pmu.msr_global_ctl;
		edx = 0;
		kvm_fep_asm("wrmsr");
	} else {
		eax = ecx = edx = 0;
		kvm_fep_asm("nop");
	}

	__stop_event(&brnch_cnt);
	__stop_event(&instr_cnt);

	// Check that the end count - start count is at least the expected
	// number of instructions and branches.
	if (this_cpu_has_perf_global_ctrl()) {
		report(instr_cnt.count - instr_start == KVM_FEP_INSNS,
		       "instruction count");
		report(brnch_cnt.count - brnch_start == KVM_FEP_BRANCHES,
		       "branch count");
	} else {
		report(instr_cnt.count - instr_start >= KVM_FEP_INSNS,
		       "instruction count");
		report(brnch_cnt.count - brnch_start >= KVM_FEP_BRANCHES,
		       "branch count");
	}

	if (this_cpu_has_perf_global_status()) {
		// Additionally check that those counters overflowed properly.
		status = rdmsr(pmu.msr_global_status);
		report(status & BIT_ULL(0), "branch counter overflow");
		report(status & BIT_ULL(1), "instruction counter overflow");
	}

	report_prefix_pop();
}

#define XBEGIN_STARTED (~0u)
static void check_tsx_cycles(void)
{
	pmu_counter_t cnt;
	unsigned int i, ret = 0;

	if (!this_cpu_has(X86_FEATURE_RTM))
		return;

	report_prefix_push("TSX cycles");

	for (i = 0; i < pmu.nr_gp_counters; i++) {
		cnt.ctr = MSR_GP_COUNTERx(i);

		if (i == 2) {
			/* Transactional cycles committed only on gp counter 2 */
			cnt.config = EVNTSEL_OS | EVNTSEL_USR | 0x30000003c;
		} else {
			/* Transactional cycles */
			cnt.config = EVNTSEL_OS | EVNTSEL_USR | 0x10000003c;
		}

		start_event(&cnt);

		asm volatile("xbegin 1f\n\t"
				"1:\n\t"
				: "+a" (ret) :: "memory");

		/* Generate a non-canonical #GP to trigger ABORT. */
		if (ret == XBEGIN_STARTED)
			*(int *)NONCANONICAL = 0;

		stop_event(&cnt);

		report(cnt.count > 0, "gp cntr-%d with a value of %" PRId64 "", i, cnt.count);
	}

	report_prefix_pop();
}

static void warm_up(void)
{
	int i;

	/*
	 * Since cycles event is always run as the first event, there would be
	 * a warm-up state to warm up the cache, it leads to the measured cycles
	 * value may exceed the pre-defined cycles upper boundary and cause
	 * false positive. To avoid this, introduce an warm-up state before
	 * the real verification.
	 */
	for (i = 0; i < 10; i++)
		loop(0);
}

static void check_counters(void)
{
	if (is_fep_available())
		check_emulated_instr();

	warm_up();
	check_gp_counters();
	check_fixed_counters();
	check_rdpmc();
	check_counters_many();
	check_counter_overflow();
	check_gp_counter_cmask();
	check_running_counter_wrmsr();
	check_tsx_cycles();
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
		.config = EVNTSEL_OS | EVNTSEL_USR |
			  intel_gp_events[INTEL_REF_CYCLES_IDX].unit_sel,
	};
	uint64_t tsc_delta;
	uint64_t t0, t1, t2, t3;

	/* Bit 2 enumerates the availability of reference cycles events. */
	if (!pmu.nr_gp_counters || !pmu_gp_counter_is_available(2))
		return;

	if (this_cpu_has_perf_global_ctrl())
		wrmsr(pmu.msr_global_ctl, 0);

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

	intel_gp_events[INTEL_REF_CYCLES_IDX].min =
		(intel_gp_events[INTEL_REF_CYCLES_IDX].min * cnt.count) / tsc_delta;
	intel_gp_events[INTEL_REF_CYCLES_IDX].max =
		(intel_gp_events[INTEL_REF_CYCLES_IDX].max * cnt.count) / tsc_delta;
}

static void check_invalid_rdpmc_gp(void)
{
	uint64_t val;

	report(rdpmc_safe(64, &val) == GP_VECTOR,
	       "Expected #GP on RDPMC(64)");
}

int main(int ac, char **av)
{
	int instruction_idx;
	int branch_idx;
	int branch_miss_idx;

	setup_vm();
	handle_irq(PMI_VECTOR, cnt_overflow);
	buf = malloc(N*64);

	check_invalid_rdpmc_gp();

	if (pmu.is_intel) {
		if (!pmu.version) {
			report_skip("No Intel Arch PMU is detected!");
			return report_summary();
		}
		gp_events = (struct pmu_event *)intel_gp_events;
		gp_events_size = sizeof(intel_gp_events)/sizeof(intel_gp_events[0]);
		instruction_idx = INTEL_INSTRUCTIONS_IDX;
		branch_idx = INTEL_BRANCHES_IDX;
		branch_miss_idx = INTEL_BRANCH_MISS_IDX;

		/*
		 * For legacy Intel CPUS without clflush/clflushopt support,
		 * there is no way to force to trigger a LLC miss, thus set
		 * the minimum value to 0 to avoid false positives.
		 */
		if (!this_cpu_has(X86_FEATURE_CLFLUSH))
			gp_events[INTEL_LLC_MISSES_IDX].min = 0;

		report_prefix_push("Intel");
		set_ref_cycle_expectations();
	} else {
		gp_events_size = sizeof(amd_gp_events)/sizeof(amd_gp_events[0]);
		gp_events = (struct pmu_event *)amd_gp_events;
		instruction_idx = AMD_INSTRUCTIONS_IDX;
		branch_idx = AMD_BRANCHES_IDX;
		branch_miss_idx = AMD_BRANCH_MISS_IDX;
		report_prefix_push("AMD");
	}
	adjust_events_range(gp_events, instruction_idx, branch_idx, branch_miss_idx);

	printf("PMU version:         %d\n", pmu.version);
	printf("GP counters:         %d\n", pmu.nr_gp_counters);
	printf("GP counter width:    %d\n", pmu.gp_counter_width);
	printf("Mask length:         %d\n", pmu.gp_counter_mask_length);
	printf("Fixed counters:      %d\n", pmu.nr_fixed_counters);
	printf("Fixed counter width: %d\n", pmu.fixed_counter_width);

	fixed_counters_num = MIN(pmu.nr_fixed_counters, ARRAY_SIZE(fixed_events));
	if (pmu.nr_fixed_counters > ARRAY_SIZE(fixed_events))
		report_info("Fixed counters number %d > defined fixed events %u.  "
			    "Please update test case.", pmu.nr_fixed_counters,
			    (unsigned)ARRAY_SIZE(fixed_events));

	apic_write(APIC_LVTPC, PMI_VECTOR);

	check_counters();

	if (pmu_has_full_writes()) {
		pmu.msr_gp_counter_base = MSR_IA32_PMC0;

		report_prefix_push("full-width writes");
		check_counters();
		check_gp_counters_write_width();
		report_prefix_pop();
	}

	if (!pmu.is_intel) {
		report_prefix_push("K7");
		pmu.nr_gp_counters = AMD64_NUM_COUNTERS;
		pmu.msr_gp_counter_base = MSR_K7_PERFCTR0;
		pmu.msr_gp_event_select_base = MSR_K7_EVNTSEL0;
		check_counters();
		report_prefix_pop();
	}

	return report_summary();
}
