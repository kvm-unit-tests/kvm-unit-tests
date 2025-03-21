// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc_page.h>
#include <cpumask.h>
#include <limits.h>
#include <memregions.h>
#include <on-cpus.h>
#include <rand.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <vmalloc.h>

#include <asm/barrier.h>
#include <asm/csr.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <asm/mmu.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/timer.h>

#include "sbi-tests.h"

#define	HIGH_ADDR_BOUNDARY	((phys_addr_t)1 << 32)

void check_sse(void);
void check_fwft(void);

static long __labs(long a)
{
	return __builtin_labs(a);
}

static void help(void)
{
	puts("Test SBI\n");
	puts("An environ must be provided where expected values are given.\n");
}

static struct sbiret sbi_base(int fid, unsigned long arg0)
{
	return sbi_ecall(SBI_EXT_BASE, fid, arg0, 0, 0, 0, 0, 0);
}

static struct sbiret sbi_dbcn_write(unsigned long num_bytes, unsigned long base_addr_lo,
				    unsigned long base_addr_hi)
{
	return sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE,
			 num_bytes, base_addr_lo, base_addr_hi, 0, 0, 0);
}

static struct sbiret sbi_dbcn_write_byte(uint8_t byte)
{
	return sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, byte, 0, 0, 0, 0, 0);
}

static struct sbiret sbi_hart_suspend_raw(unsigned long suspend_type, unsigned long resume_addr, unsigned long opaque)
{
	return sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_SUSPEND, suspend_type, resume_addr, opaque, 0, 0, 0);
}

static struct sbiret sbi_system_suspend_raw(unsigned long sleep_type, unsigned long resume_addr, unsigned long opaque)
{
	return sbi_ecall(SBI_EXT_SUSP, 0, sleep_type, resume_addr, opaque, 0, 0, 0);
}

void sbi_bad_fid(int ext)
{
	struct sbiret ret = sbi_ecall(ext, 0xbad, 0, 0, 0, 0, 0, 0);
	sbiret_report_error(&ret, SBI_ERR_NOT_SUPPORTED, "Bad FID");
}

static void start_cpu(void *data)
{
	/* nothing to do */
}

static void stop_cpu(void *data)
{
	struct sbiret ret = sbi_hart_stop();
	assert_msg(0, "cpu%d (hartid = %lx) failed to stop with sbiret.error %ld",
		   smp_processor_id(), current_thread_info()->hartid, ret.error);
}

static int rand_online_cpu(prng_state *ps)
{
	int cpu, me = smp_processor_id();

	for (;;) {
		cpu = prng32(ps) % nr_cpus;
		cpu = cpumask_next(cpu - 1, &cpu_present_mask);
		if (cpu != nr_cpus && cpu != me && cpu_present(cpu))
			break;
	}

	return cpu;
}

static void split_phys_addr(phys_addr_t paddr, unsigned long *hi, unsigned long *lo)
{
	*lo = (unsigned long)paddr;
	*hi = 0;
	if (__riscv_xlen == 32)
		*hi = (unsigned long)(paddr >> 32);
}

static bool check_addr(phys_addr_t start, phys_addr_t size)
{
	struct mem_region *r = memregions_find(start);
	return r && r->end - start >= size && r->flags == MR_F_UNUSED;
}

static phys_addr_t get_highest_addr(void)
{
	phys_addr_t highest_end = 0;
	struct mem_region *r;

	for (r = mem_regions; r->end; ++r) {
		if (r->end > highest_end)
			highest_end = r->end;
	}

	return highest_end - 1;
}

static bool get_invalid_addr(phys_addr_t *paddr, bool allow_default)
{
	if (env_enabled("INVALID_ADDR_AUTO")) {
		*paddr = get_highest_addr() + 1;
		return true;
	} else if (allow_default && !getenv("INVALID_ADDR")) {
		*paddr = -1ul;
		return true;
	} else if (env_or_skip("INVALID_ADDR")) {
		*paddr = strtoull(getenv("INVALID_ADDR"), NULL, 0);
		return true;
	}

	return false;
}

static void timer_setup(void (*handler)(struct pt_regs *))
{
	install_irq_handler(IRQ_S_TIMER, handler);
	timer_irq_enable();
}

static void timer_teardown(void)
{
	timer_irq_disable();
	timer_stop();
	install_irq_handler(IRQ_S_TIMER, NULL);
}

static void check_base(void)
{
	struct sbiret ret;
	long expected;

	report_prefix_push("base");

	sbi_bad_fid(SBI_EXT_BASE);

	ret = sbi_base(SBI_EXT_BASE_GET_SPEC_VERSION, 0);

	report_prefix_push("spec_version");
	if (env_or_skip("SBI_SPEC_VERSION")) {
		expected = (long)strtoul(getenv("SBI_SPEC_VERSION"), NULL, 0);
		assert_msg(!(expected & BIT(31)), "SBI spec version bit 31 must be zero");
		assert_msg(__riscv_xlen == 32 || !(expected >> 32), "SBI spec version bits greater than 31 must be zero");
		sbiret_check(&ret, 0, expected);
	}
	report_prefix_pop();

	ret.value &= 0x7ffffffful;

	if (ret.error || ret.value < 2) {
		report_skip("SBI spec version 0.2 or higher required");
		return;
	}

	report_prefix_push("impl_id");
	if (env_or_skip("SBI_IMPL_ID")) {
		expected = (long)strtoul(getenv("SBI_IMPL_ID"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_IMP_ID, 0);
		sbiret_check(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("impl_version");
	if (env_or_skip("SBI_IMPL_VERSION")) {
		expected = (long)strtoul(getenv("SBI_IMPL_VERSION"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_IMP_VERSION, 0);
		sbiret_check(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("probe_ext");
	expected = getenv("SBI_PROBE_EXT") ? (long)strtoul(getenv("SBI_PROBE_EXT"), NULL, 0) : 1;
	ret = sbi_base(SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE);
	sbiret_check(&ret, 0, expected);
	report_prefix_push("unavailable");
	ret = sbi_base(SBI_EXT_BASE_PROBE_EXT, 0xb000000);
	sbiret_check(&ret, 0, 0);
	report_prefix_popn(2);

	report_prefix_push("mvendorid");
	if (env_or_skip("MVENDORID")) {
		expected = (long)strtoul(getenv("MVENDORID"), NULL, 0);
		assert(__riscv_xlen == 32 || !(expected >> 32));
		ret = sbi_base(SBI_EXT_BASE_GET_MVENDORID, 0);
		sbiret_check(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("marchid");
	if (env_or_skip("MARCHID")) {
		expected = (long)strtoul(getenv("MARCHID"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_MARCHID, 0);
		sbiret_check(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("mimpid");
	if (env_or_skip("MIMPID")) {
		expected = (long)strtoul(getenv("MIMPID"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_MIMPID, 0);
		sbiret_check(&ret, 0, expected);
	}
	report_prefix_popn(2);
}

struct timer_info {
	bool timer_works;
	bool mask_timer_irq;
	bool timer_irq_set;
	bool timer_irq_cleared;
	unsigned long timer_irq_count;
};

static struct timer_info timer_info;

static bool timer_irq_pending(void)
{
	return csr_read(CSR_SIP) & IP_TIP;
}

static void timer_irq_handler(struct pt_regs *regs)
{
	timer_info.timer_works = true;

	if (timer_info.timer_irq_count < ULONG_MAX)
		++timer_info.timer_irq_count;

	if (timer_irq_pending())
		timer_info.timer_irq_set = true;

	if (timer_info.mask_timer_irq)
		timer_irq_disable();
	else
		sbi_set_timer(ULONG_MAX);

	if (!timer_irq_pending())
		timer_info.timer_irq_cleared = true;
}

static void timer_check_set_timer(bool mask_timer_irq)
{
	struct sbiret ret;
	unsigned long begin, end, duration;
	const char *mask_test_str = mask_timer_irq ? " for mask irq test" : "";
	unsigned long d = getenv("SBI_TIMER_DELAY") ? strtol(getenv("SBI_TIMER_DELAY"), NULL, 0) : 200000;
	unsigned long margin = getenv("SBI_TIMER_MARGIN") ? strtol(getenv("SBI_TIMER_MARGIN"), NULL, 0) : 200000;

	d = usec_to_cycles(d);
	margin = usec_to_cycles(margin);

	timer_info = (struct timer_info){ .mask_timer_irq = mask_timer_irq };
	begin = timer_get_cycles();
	ret = sbi_set_timer(begin + d);

	report(!ret.error, "set timer%s", mask_test_str);
	if (ret.error)
		report_info("set timer%s failed with %ld\n", mask_test_str, ret.error);

	while ((end = timer_get_cycles()) <= (begin + d + margin) && !timer_info.timer_works)
		cpu_relax();

	report(timer_info.timer_works, "timer interrupt received%s", mask_test_str);
	report(timer_info.timer_irq_set, "pending timer interrupt bit set in irq handler%s", mask_test_str);

	if (!mask_timer_irq) {
		report(timer_info.timer_irq_set && timer_info.timer_irq_cleared,
		       "pending timer interrupt bit cleared by setting timer to -1");
	}

	if (timer_info.timer_works) {
		duration = end - begin;
		report(duration >= d && duration <= (d + margin), "timer delay honored%s", mask_test_str);
	}

	report(timer_info.timer_irq_count == 1, "timer interrupt received exactly once%s", mask_test_str);
}

static void check_time(void)
{
	bool pending;

	report_prefix_push("time");

	if (!sbi_probe(SBI_EXT_TIME)) {
		report_skip("time extension not available");
		report_prefix_pop();
		return;
	}

	sbi_bad_fid(SBI_EXT_TIME);

	report_prefix_push("set_timer");

	install_irq_handler(IRQ_S_TIMER, timer_irq_handler);
	local_irq_enable();
	timer_irq_enable();

	timer_check_set_timer(false);

	if (csr_read(CSR_SIE) & IE_TIE)
		timer_check_set_timer(true);
	else
		report_skip("timer irq enable bit is not writable, skipping mask irq test");

	timer_irq_disable();
	sbi_set_timer(0);
	pending = timer_irq_pending();
	report(pending, "timer immediately pending by setting timer to 0");
	sbi_set_timer(ULONG_MAX);
	if (pending)
		report(!timer_irq_pending(), "pending timer cleared while masked");
	else
		report_skip("timer is not pending, skipping timer cleared while masked test");

	local_irq_disable();
	install_irq_handler(IRQ_S_TIMER, NULL);

	report_prefix_popn(2);
}

static bool ipi_received[NR_CPUS];
static bool ipi_timeout[NR_CPUS];
static cpumask_t ipi_done;

static void ipi_timeout_handler(struct pt_regs *regs)
{
	timer_stop();
	ipi_timeout[smp_processor_id()] = true;
}

static void ipi_irq_handler(struct pt_regs *regs)
{
	ipi_ack();
	ipi_received[smp_processor_id()] = true;
}

static void ipi_hart_wait(void *data)
{
	unsigned long timeout = (unsigned long)data;
	int me = smp_processor_id();

	install_irq_handler(IRQ_S_SOFT, ipi_irq_handler);
	install_irq_handler(IRQ_S_TIMER, ipi_timeout_handler);
	local_ipi_enable();
	timer_irq_enable();
	local_irq_enable();

	timer_start(timeout);
	while (!READ_ONCE(ipi_received[me]) && !READ_ONCE(ipi_timeout[me]))
		cpu_relax();
	local_irq_disable();
	timer_stop();
	local_ipi_disable();
	timer_irq_disable();
	install_irq_handler(IRQ_S_SOFT, NULL);
	install_irq_handler(IRQ_S_TIMER, NULL);

	cpumask_set_cpu(me, &ipi_done);
}

static void ipi_hart_check(cpumask_t *mask)
{
	int cpu;

	for_each_cpu(cpu, mask) {
		if (ipi_timeout[cpu]) {
			const char *rec = ipi_received[cpu] ? "but was still received"
							    : "and has still not been received";
			report_fail("ipi timed out on cpu%d %s", cpu, rec);
		}

		ipi_timeout[cpu] = false;
		ipi_received[cpu] = false;
	}
}

static void check_ipi(void)
{
	unsigned long d = getenv("SBI_IPI_TIMEOUT") ? strtol(getenv("SBI_IPI_TIMEOUT"), NULL, 0) : 200000;
	int nr_cpus_present = cpumask_weight(&cpu_present_mask);
	int me = smp_processor_id();
	unsigned long max_hartid = 0;
	unsigned long hartid1, hartid2;
	cpumask_t ipi_receivers;
	static prng_state ps;
	struct sbiret ret;
	int cpu, cpu2;

	ps = prng_init(0xDEADBEEF);

	report_prefix_push("ipi");

	if (!sbi_probe(SBI_EXT_IPI)) {
		report_skip("ipi extension not available");
		report_prefix_pop();
		return;
	}

	sbi_bad_fid(SBI_EXT_IPI);

	if (nr_cpus_present < 2) {
		report_skip("At least 2 cpus required");
		report_prefix_pop();
		return;
	}

	report_prefix_push("random hart");
	cpumask_clear(&ipi_done);
	cpumask_clear(&ipi_receivers);
	cpu = rand_online_cpu(&ps);
	cpumask_set_cpu(cpu, &ipi_receivers);
	on_cpu_async(cpu, ipi_hart_wait, (void *)d);
	ret = sbi_send_ipi_cpu(cpu);
	report(ret.error == SBI_SUCCESS, "ipi returned success");
	while (!cpumask_equal(&ipi_done, &ipi_receivers))
		cpu_relax();
	ipi_hart_check(&ipi_receivers);
	report_prefix_pop();

	report_prefix_push("two in hart_mask");

	if (nr_cpus_present < 3) {
		report_skip("3 cpus required");
		goto end_two;
	}

	cpu = rand_online_cpu(&ps);
	hartid1 = cpus[cpu].hartid;
	hartid2 = 0;
	for_each_present_cpu(cpu2) {
		if (cpu2 == cpu || cpu2 == me)
			continue;
		hartid2 = cpus[cpu2].hartid;
		if (__labs(hartid2 - hartid1) < BITS_PER_LONG)
			break;
	}
	if (cpu2 == nr_cpus) {
		report_skip("hartids are too sparse");
		goto end_two;
	}

	cpumask_clear(&ipi_done);
	cpumask_clear(&ipi_receivers);
	cpumask_set_cpu(cpu, &ipi_receivers);
	cpumask_set_cpu(cpu2, &ipi_receivers);
	on_cpu_async(cpu, ipi_hart_wait, (void *)d);
	on_cpu_async(cpu2, ipi_hart_wait, (void *)d);
	ret = sbi_send_ipi((1UL << __labs(hartid2 - hartid1)) | 1UL, hartid1 < hartid2 ? hartid1 : hartid2);
	report(ret.error == SBI_SUCCESS, "ipi returned success");
	while (!cpumask_equal(&ipi_done, &ipi_receivers))
		cpu_relax();
	ipi_hart_check(&ipi_receivers);
end_two:
	report_prefix_pop();

	report_prefix_push("broadcast");
	cpumask_clear(&ipi_done);
	cpumask_copy(&ipi_receivers, &cpu_present_mask);
	cpumask_clear_cpu(me, &ipi_receivers);
	on_cpumask_async(&ipi_receivers, ipi_hart_wait, (void *)d);
	ret = sbi_send_ipi_broadcast();
	report(ret.error == SBI_SUCCESS, "ipi returned success");
	while (!cpumask_equal(&ipi_done, &ipi_receivers))
		cpu_relax();
	ipi_hart_check(&ipi_receivers);
	report_prefix_pop();

	report_prefix_push("invalid parameters");

	for_each_present_cpu(cpu) {
		if (cpus[cpu].hartid > max_hartid)
			max_hartid = cpus[cpu].hartid;
	}

	/* Test no targets */
	ret = sbi_send_ipi(0, 0);
	sbiret_report_error(&ret, SBI_SUCCESS, "no targets, hart_mask_base is 0");
	ret = sbi_send_ipi(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "no targets, hart_mask_base is 1");

	/* Try the next higher hartid than the max */
	bool kfail = __sbi_get_imp_id() == SBI_IMPL_OPENSBI &&
		     __sbi_get_imp_version() < sbi_impl_opensbi_mk_version(1, 7);
	ret = sbi_send_ipi(2, max_hartid);
	sbiret_kfail_error(kfail, &ret, SBI_ERR_INVALID_PARAM, "hart_mask");
	ret = sbi_send_ipi(1, max_hartid + 1);
	sbiret_kfail_error(kfail, &ret, SBI_ERR_INVALID_PARAM, "hart_mask_base");

	report_prefix_pop();

	report_prefix_pop();
}

unsigned char sbi_hsm_stop_hart[NR_CPUS];
unsigned char sbi_hsm_hart_start_checks[NR_CPUS];
unsigned char sbi_hsm_non_retentive_hart_suspend_checks[NR_CPUS];

static const char * const hart_state_str[] = {
	[SBI_EXT_HSM_STARTED] = "started",
	[SBI_EXT_HSM_STOPPED] = "stopped",
	[SBI_EXT_HSM_SUSPENDED] = "suspended",
};
struct hart_state_transition_info {
	enum sbi_ext_hsm_sid initial_state;
	enum sbi_ext_hsm_sid intermediate_state;
	enum sbi_ext_hsm_sid final_state;
};
static cpumask_t sbi_hsm_started_hart_checks;
static bool sbi_hsm_invalid_hartid_check;
static bool sbi_hsm_timer_fired;
extern void sbi_hsm_check_hart_start(void);
extern void sbi_hsm_check_non_retentive_suspend(void);

static void hsm_timer_irq_handler(struct pt_regs *regs)
{
	timer_stop();
	sbi_hsm_timer_fired = true;
}

static void hart_check_already_started(void *data)
{
	struct sbiret ret;
	unsigned long hartid = current_thread_info()->hartid;
	int me = smp_processor_id();

	ret = sbi_hart_start(hartid, virt_to_phys(&start_cpu), 0);

	if (ret.error == SBI_ERR_ALREADY_AVAILABLE)
		cpumask_set_cpu(me, &sbi_hsm_started_hart_checks);
}

static void hart_start_invalid_hartid(void *data)
{
	struct sbiret ret;

	ret = sbi_hart_start(-1UL, virt_to_phys(&start_cpu), 0);

	if (ret.error == SBI_ERR_INVALID_PARAM)
		sbi_hsm_invalid_hartid_check = true;
}

static cpumask_t hsm_suspend_not_supported;

static void ipi_nop(struct pt_regs *regs)
{
	ipi_ack();
}

static void hart_suspend_and_wait_ipi(unsigned long suspend_type, unsigned long resume_addr,
				      unsigned long opaque, bool returns, const char *typestr)
{
	unsigned long hartid = current_thread_info()->hartid;
	struct sbiret ret;

	install_irq_handler(IRQ_S_SOFT, ipi_nop);
	local_ipi_enable();
	local_irq_enable();

	ret = sbi_hart_suspend_raw(suspend_type, resume_addr, opaque);
	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		cpumask_set_cpu(smp_processor_id(), &hsm_suspend_not_supported);
	else if (ret.error)
		report_fail("failed to %s cpu%d (hartid = %lx) (error=%ld)",
			    typestr, smp_processor_id(), hartid, ret.error);
	else if (!returns)
		report_fail("failed to %s cpu%d (hartid = %lx) (call should not return)",
			    typestr, smp_processor_id(), hartid);

	local_irq_disable();
	local_ipi_disable();
	install_irq_handler(IRQ_S_SOFT, NULL);
}

static void hart_retentive_suspend(void *data)
{
	hart_suspend_and_wait_ipi(SBI_EXT_HSM_HART_SUSPEND_RETENTIVE, 0, 0, true, "retentive suspend");
}

static void hart_non_retentive_suspend(void *data)
{
	unsigned long params[] = {
		[SBI_HSM_MAGIC_IDX] = SBI_HSM_MAGIC,
		[SBI_HSM_HARTID_IDX] = current_thread_info()->hartid,
	};

	hart_suspend_and_wait_ipi(SBI_EXT_HSM_HART_SUSPEND_NON_RETENTIVE,
				  virt_to_phys(&sbi_hsm_check_non_retentive_suspend), virt_to_phys(params),
				  false, "non-retentive suspend");
}

/* This test function is only being run on RV64 to verify that upper bits of suspend_type are ignored */
static void hart_retentive_suspend_with_msb_set(void *data)
{
	unsigned long suspend_type = SBI_EXT_HSM_HART_SUSPEND_RETENTIVE | (_AC(1, UL) << (__riscv_xlen - 1));

	hart_suspend_and_wait_ipi(suspend_type, 0, 0, true, "retentive suspend with MSB set");
}

/* This test function is only being run on RV64 to verify that upper bits of suspend_type are ignored */
static void hart_non_retentive_suspend_with_msb_set(void *data)
{
	unsigned long suspend_type = SBI_EXT_HSM_HART_SUSPEND_NON_RETENTIVE | (_AC(1, UL) << (__riscv_xlen - 1));
	unsigned long params[] = {
		[SBI_HSM_MAGIC_IDX] = SBI_HSM_MAGIC,
		[SBI_HSM_HARTID_IDX] = current_thread_info()->hartid,
	};

	hart_suspend_and_wait_ipi(suspend_type,
				  virt_to_phys(&sbi_hsm_check_non_retentive_suspend), virt_to_phys(params),
				  false, "non-retentive suspend with MSB set");
}

static bool hart_wait_on_status(unsigned long hartid, enum sbi_ext_hsm_sid status, unsigned long duration)
{
	struct sbiret ret;

	sbi_hsm_timer_fired = false;
	timer_start(duration);

	ret = sbi_hart_get_status(hartid);

	while (!ret.error && ret.value == status && !sbi_hsm_timer_fired) {
		cpu_relax();
		ret = sbi_hart_get_status(hartid);
	}

	timer_stop();

	if (sbi_hsm_timer_fired)
		report_info("timer fired while waiting on status %u for hartid %lx", status, hartid);
	else if (ret.error)
		report_fail("got %ld while waiting on status %u for hartid %lx", ret.error, status, hartid);

	return !sbi_hsm_timer_fired && !ret.error;
}

static int hart_wait_state_transition(cpumask_t *mask, unsigned long duration,
				      struct hart_state_transition_info *states)
{
	struct sbiret ret;
	unsigned long hartid;
	int cpu, count = 0;

	for_each_cpu(cpu, mask) {
		hartid = cpus[cpu].hartid;
		if (!hart_wait_on_status(hartid, states->initial_state, duration))
			continue;
		if (!hart_wait_on_status(hartid, states->intermediate_state, duration))
			continue;

		ret = sbi_hart_get_status(hartid);
		if (ret.error)
			report_info("hartid %lx get status failed (error=%ld)", hartid, ret.error);
		else if (ret.value != states->final_state)
			report_info("hartid %lx status is not '%s' (ret.value=%ld)", hartid,
				    hart_state_str[states->final_state], ret.value);
		else
			count++;
	}

	return count;
}

static void hart_wait_until_idle(cpumask_t *mask, unsigned long duration)
{
	sbi_hsm_timer_fired = false;
	timer_start(duration);

	while (!cpumask_subset(mask, &cpu_idle_mask) && !sbi_hsm_timer_fired)
		cpu_relax();

	timer_stop();

	if (sbi_hsm_timer_fired)
		report_info("hsm timer fired before all cpus became idle");
}

static void check_hsm(void)
{
	struct sbiret ret;
	unsigned long hartid;
	cpumask_t secondary_cpus_mask, mask, resume_mask;
	struct hart_state_transition_info transition_states;
	bool ipi_unavailable = false;
	int cpu, me = smp_processor_id();
	int max_cpus = getenv("SBI_MAX_CPUS") ? strtol(getenv("SBI_MAX_CPUS"), NULL, 0) : nr_cpus;
	unsigned long hsm_timer_duration = getenv("SBI_HSM_TIMER_DURATION")
					 ? strtol(getenv("SBI_HSM_TIMER_DURATION"), NULL, 0) : 200000;
	unsigned long sbi_hsm_hart_start_params[NR_CPUS * SBI_HSM_NUM_OF_PARAMS];
	int count, check, expected_count, resume_count;

	max_cpus = MIN(MIN(max_cpus, nr_cpus), cpumask_weight(&cpu_present_mask));

	report_prefix_push("hsm");

	if (!sbi_probe(SBI_EXT_HSM)) {
		report_skip("hsm extension not available");
		report_prefix_pop();
		return;
	}

	sbi_bad_fid(SBI_EXT_HSM);

	report_prefix_push("hart_get_status");

	hartid = current_thread_info()->hartid;
	ret = sbi_hart_get_status(hartid);

	if (ret.error) {
		report_fail("failed to get status of current hart (error=%ld)", ret.error);
		report_prefix_popn(2);
		return;
	} else if (ret.value != SBI_EXT_HSM_STARTED) {
		report_fail("current hart is not started (ret.value=%ld)", ret.value);
		report_prefix_popn(2);
		return;
	}

	report_pass("status of current hart is started");

	report_prefix_pop();

	if (max_cpus < 2) {
		report_skip("no other cpus to run the remaining hsm tests on");
		report_prefix_pop();
		return;
	}

	report_prefix_push("hart_stop");

	cpumask_copy(&secondary_cpus_mask, &cpu_present_mask);
	cpumask_clear_cpu(me, &secondary_cpus_mask);
	timer_setup(hsm_timer_irq_handler);
	local_irq_enable();

	/* Assume that previous tests have not cleaned up and stopped the secondary harts */
	on_cpumask_async(&secondary_cpus_mask, stop_cpu, NULL);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_STOP_PENDING,
		.final_state = SBI_EXT_HSM_STOPPED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);

	report(count == max_cpus - 1, "all secondary harts stopped");

	report_prefix_pop();

	report_prefix_push("hart_start");

	for_each_cpu(cpu, &secondary_cpus_mask) {
		hartid = cpus[cpu].hartid;
		sbi_hsm_hart_start_params[cpu * SBI_HSM_NUM_OF_PARAMS + SBI_HSM_MAGIC_IDX] = SBI_HSM_MAGIC;
		sbi_hsm_hart_start_params[cpu * SBI_HSM_NUM_OF_PARAMS + SBI_HSM_HARTID_IDX] = hartid;

		ret = sbi_hart_start(hartid, virt_to_phys(&sbi_hsm_check_hart_start),
				     virt_to_phys(&sbi_hsm_hart_start_params[cpu * SBI_HSM_NUM_OF_PARAMS]));
		if (ret.error) {
			report_fail("failed to start test on cpu%d (hartid = %lx) (error=%ld)", cpu, hartid, ret.error);
			continue;
		}
	}

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STOPPED,
		.intermediate_state = SBI_EXT_HSM_START_PENDING,
		.final_state = SBI_EXT_HSM_STARTED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);
	check = 0;

	for_each_cpu(cpu, &secondary_cpus_mask) {
		sbi_hsm_timer_fired = false;
		timer_start(hsm_timer_duration);

		while (!(READ_ONCE(sbi_hsm_hart_start_checks[cpu]) & SBI_HSM_TEST_DONE) && !sbi_hsm_timer_fired)
			cpu_relax();

		timer_stop();

		if (sbi_hsm_timer_fired) {
			report_info("hsm timer fired before cpu%d (hartid = %lx) is done with start checks", cpu, hartid);
			continue;
		}

		if (!(sbi_hsm_hart_start_checks[cpu] & SBI_HSM_TEST_SATP))
			report_info("satp is not zero for test on cpu%d (hartid = %lx)", cpu, hartid);
		else if (!(sbi_hsm_hart_start_checks[cpu] & SBI_HSM_TEST_SIE))
			report_info("sstatus.SIE is not zero for test on cpu%d (hartid = %lx)", cpu, hartid);
		else if (!(sbi_hsm_hart_start_checks[cpu] & SBI_HSM_TEST_MAGIC_A1))
			report_info("a1 does not start with magic for test on cpu%d (hartid = %lx)", cpu, hartid);
		else if (!(sbi_hsm_hart_start_checks[cpu] & SBI_HSM_TEST_HARTID_A0))
			report_info("a0 is not hartid for test on cpu %d (hartid = %lx)", cpu, hartid);
		else
			check++;
	}

	report(count == max_cpus - 1, "all secondary harts started");
	report(check == max_cpus - 1, "all secondary harts have expected register values after hart start");

	report_prefix_pop();

	report_prefix_push("hart_stop");

	memset(sbi_hsm_stop_hart, 1, sizeof(sbi_hsm_stop_hart));

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_STOP_PENDING,
		.final_state = SBI_EXT_HSM_STOPPED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);

	report(count == max_cpus - 1, "all secondary harts stopped");

	/* Reset the stop flags so that we can reuse them after suspension tests */
	memset(sbi_hsm_stop_hart, 0, sizeof(sbi_hsm_stop_hart));

	report_prefix_pop();

	report_prefix_push("hart_start");

	/* Select just one secondary cpu to run the invalid hartid test */
	on_cpu(cpumask_next(-1, &secondary_cpus_mask), hart_start_invalid_hartid, NULL);

	report(sbi_hsm_invalid_hartid_check, "secondary hart refuse to start with invalid hartid");

	on_cpumask_async(&secondary_cpus_mask, hart_check_already_started, NULL);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STOPPED,
		.intermediate_state = SBI_EXT_HSM_START_PENDING,
		.final_state = SBI_EXT_HSM_STARTED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);

	report(count == max_cpus - 1, "all secondary harts started");

	hart_wait_until_idle(&secondary_cpus_mask, hsm_timer_duration);

	report(cpumask_weight(&sbi_hsm_started_hart_checks) == max_cpus - 1,
	       "all secondary harts are already started");

	report_prefix_pop();

	report_prefix_push("hart_suspend");

	if (!sbi_probe(SBI_EXT_IPI)) {
		report_skip("skipping suspension tests since ipi extension is unavailable");
		report_prefix_pop();
		ipi_unavailable = true;
		goto sbi_hsm_hart_stop_tests;
	}

	cpumask_clear(&hsm_suspend_not_supported);
	on_cpumask_async(&secondary_cpus_mask, hart_retentive_suspend, NULL);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_SUSPEND_PENDING,
		.final_state = SBI_EXT_HSM_SUSPENDED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);

	expected_count = max_cpus - 1 - cpumask_weight(&hsm_suspend_not_supported);

	if (expected_count != 0) {
		if (expected_count != max_cpus - 1)
			report_info("not all harts support retentive suspend");
		report(count == expected_count, "supporting secondary harts retentive suspended");
	} else {
		report_skip("retentive suspend not supported by any harts");
		goto nonret_suspend_tests;
	}

	cpumask_andnot(&resume_mask, &secondary_cpus_mask, &hsm_suspend_not_supported);
	resume_count = cpumask_weight(&resume_mask);

	/* Ignore the return value since we check the status of each hart anyway */
	sbi_send_ipi_cpumask(&resume_mask);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_SUSPENDED,
		.intermediate_state = SBI_EXT_HSM_RESUME_PENDING,
		.final_state = SBI_EXT_HSM_STARTED,
	};
	count = hart_wait_state_transition(&resume_mask, hsm_timer_duration, &transition_states);

	report(count == resume_count, "supporting secondary harts retentive resumed");

nonret_suspend_tests:
	hart_wait_until_idle(&secondary_cpus_mask, hsm_timer_duration);

	cpumask_clear(&hsm_suspend_not_supported);
	on_cpumask_async(&secondary_cpus_mask, hart_non_retentive_suspend, NULL);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_SUSPEND_PENDING,
		.final_state = SBI_EXT_HSM_SUSPENDED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);

	expected_count = max_cpus - 1 - cpumask_weight(&hsm_suspend_not_supported);

	if (expected_count != 0) {
		if (expected_count != max_cpus - 1)
			report_info("not all harts support non-retentive suspend");
		report(count == expected_count, "supporting secondary harts non-retentive suspended");
	} else {
		report_skip("non-retentive suspend not supported by any harts");
		goto hsm_suspend_tests_done;
	}

	cpumask_andnot(&resume_mask, &secondary_cpus_mask, &hsm_suspend_not_supported);
	resume_count = cpumask_weight(&resume_mask);

	/* Ignore the return value since we check the status of each hart anyway */
	sbi_send_ipi_cpumask(&resume_mask);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_SUSPENDED,
		.intermediate_state = SBI_EXT_HSM_RESUME_PENDING,
		.final_state = SBI_EXT_HSM_STARTED,
	};
	count = hart_wait_state_transition(&resume_mask, hsm_timer_duration, &transition_states);
	check = 0;

	for_each_cpu(cpu, &resume_mask) {
		sbi_hsm_timer_fired = false;
		timer_start(hsm_timer_duration);

		while (!(READ_ONCE(sbi_hsm_non_retentive_hart_suspend_checks[cpu]) & SBI_HSM_TEST_DONE) && !sbi_hsm_timer_fired)
			cpu_relax();

		timer_stop();

		if (sbi_hsm_timer_fired) {
			report_info("hsm timer fired before hart %ld is done with non-retentive resume checks", hartid);
			continue;
		}

		if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_SATP))
			report_info("satp is not zero for test on cpu%d (hartid = %lx)", cpu, hartid);
		else if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_SIE))
			report_info("sstatus.SIE is not zero for test on cpu%d (hartid = %lx)", cpu, hartid);
		else if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_MAGIC_A1))
			report_info("a1 does not start with magic for test on cpu%d (hartid = %lx)", cpu, hartid);
		else if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_HARTID_A0))
			report_info("a0 is not hartid for test on cpu%d (hartid = %lx)", cpu, hartid);
		else
			check++;
	}

	report(count == resume_count, "supporting secondary harts non-retentive resumed");
	report(check == resume_count, "supporting secondary harts have expected register values after non-retentive resume");

hsm_suspend_tests_done:
	report_prefix_pop();

sbi_hsm_hart_stop_tests:
	report_prefix_push("hart_stop");

	if (ipi_unavailable || expected_count == 0)
		on_cpumask_async(&secondary_cpus_mask, stop_cpu, NULL);
	else
		memset(sbi_hsm_stop_hart, 1, sizeof(sbi_hsm_stop_hart));

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_STOP_PENDING,
		.final_state = SBI_EXT_HSM_STOPPED,
	};
	count = hart_wait_state_transition(&secondary_cpus_mask, hsm_timer_duration, &transition_states);

	report(count == max_cpus - 1, "all secondary harts stopped");

	report_prefix_pop();

	if (__riscv_xlen == 32 || ipi_unavailable) {
		local_irq_disable();
		timer_teardown();
		report_prefix_pop();
		return;
	}

	report_prefix_push("hart_suspend");

	/* Select just one secondary cpu to run suspension tests with MSB of suspend type being set */
	cpu = cpumask_next(-1, &secondary_cpus_mask);
	hartid = cpus[cpu].hartid;
	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);

	/* Boot up the secondary cpu and let it proceed to the idle loop */
	on_cpu(cpu, start_cpu, NULL);

	cpumask_clear(&hsm_suspend_not_supported);
	on_cpu_async(cpu, hart_retentive_suspend_with_msb_set, NULL);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_SUSPEND_PENDING,
		.final_state = SBI_EXT_HSM_SUSPENDED,
	};
	count = hart_wait_state_transition(&mask, hsm_timer_duration, &transition_states);

	expected_count = 1 - cpumask_weight(&hsm_suspend_not_supported);

	if (expected_count) {
		report(count == expected_count, "retentive suspend with MSB set");
	} else {
		report_skip("retentive suspend not supported by cpu%d", cpu);
		goto nonret_suspend_with_msb;
	}

	/* Ignore the return value since we manually validate the status of the hart anyway */
	sbi_send_ipi_cpu(cpu);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_SUSPENDED,
		.intermediate_state = SBI_EXT_HSM_RESUME_PENDING,
		.final_state = SBI_EXT_HSM_STARTED,
	};
	count = hart_wait_state_transition(&mask, hsm_timer_duration, &transition_states);

	report(count, "secondary hart retentive resumed with MSB set");

nonret_suspend_with_msb:
	/* Reset these flags so that we can reuse them for the non-retentive suspension test */
	sbi_hsm_stop_hart[cpu] = 0;
	sbi_hsm_non_retentive_hart_suspend_checks[cpu] = 0;

	cpumask_clear(&hsm_suspend_not_supported);
	on_cpu_async(cpu, hart_non_retentive_suspend_with_msb_set, NULL);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_SUSPEND_PENDING,
		.final_state = SBI_EXT_HSM_SUSPENDED,
	};
	count = hart_wait_state_transition(&mask, hsm_timer_duration, &transition_states);

	expected_count = 1 - cpumask_weight(&hsm_suspend_not_supported);

	if (expected_count) {
		report(count == expected_count, "non-retentive suspend with MSB set");
	} else {
		report_skip("non-retentive suspend not supported by cpu%d", cpu);
		goto hsm_hart_stop_test;
	}

	/* Ignore the return value since we manually validate the status of the hart anyway */
	sbi_send_ipi_cpu(cpu);

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_SUSPENDED,
		.intermediate_state = SBI_EXT_HSM_RESUME_PENDING,
		.final_state = SBI_EXT_HSM_STARTED,
	};
	count = hart_wait_state_transition(&mask, hsm_timer_duration, &transition_states);
	check = 0;

	if (count) {
		sbi_hsm_timer_fired = false;
		timer_start(hsm_timer_duration);

		while (!(READ_ONCE(sbi_hsm_non_retentive_hart_suspend_checks[cpu]) & SBI_HSM_TEST_DONE) && !sbi_hsm_timer_fired)
			cpu_relax();

		timer_stop();

		if (sbi_hsm_timer_fired) {
			report_info("hsm timer fired before cpu%d (hartid = %lx) is done with non-retentive resume checks", cpu, hartid);
		} else {
			if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_SATP))
				report_info("satp is not zero for test on cpu%d (hartid = %lx)", cpu, hartid);
			else if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_SIE))
				report_info("sstatus.SIE is not zero for test on cpu%d (hartid = %lx)", cpu, hartid);
			else if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_MAGIC_A1))
				report_info("a1 does not start with magic for test on cpu%d (hartid = %lx)", cpu, hartid);
			else if (!(sbi_hsm_non_retentive_hart_suspend_checks[cpu] & SBI_HSM_TEST_HARTID_A0))
				report_info("a0 is not hartid for test on cpu%d (hartid = %lx)", cpu, hartid);
			else
				check = 1;
		}
	}

	report(count, "secondary hart non-retentive resumed with MSB set");
	report(check, "secondary hart has expected register values after non-retentive resume with MSB set");

hsm_hart_stop_test:
	report_prefix_pop();

	report_prefix_push("hart_stop");

	if (expected_count == 0)
		on_cpu_async(cpu, stop_cpu, NULL);
	else
		sbi_hsm_stop_hart[cpu] = 1;

	transition_states = (struct hart_state_transition_info) {
		.initial_state = SBI_EXT_HSM_STARTED,
		.intermediate_state = SBI_EXT_HSM_STOP_PENDING,
		.final_state = SBI_EXT_HSM_STOPPED,
	};
	count = hart_wait_state_transition(&mask, hsm_timer_duration, &transition_states);

	report(count, "secondary hart stopped after suspension tests with MSB set");

	local_irq_disable();
	timer_teardown();
	report_prefix_popn(2);
}

#define DBCN_WRITE_TEST_STRING		"DBCN_WRITE_TEST_STRING\n"
#define DBCN_WRITE_BYTE_TEST_BYTE	((u8)'a')

static void dbcn_write_test(const char *s, unsigned long num_bytes, bool xfail)
{
	unsigned long base_addr_lo, base_addr_hi;
	phys_addr_t paddr = virt_to_phys((void *)s);
	int num_calls = 0;
	struct sbiret ret;

	split_phys_addr(paddr, &base_addr_hi, &base_addr_lo);

	do {
		ret = sbi_dbcn_write(num_bytes, base_addr_lo, base_addr_hi);
		num_bytes -= ret.value;
		paddr += ret.value;
		split_phys_addr(paddr, &base_addr_hi, &base_addr_lo);
		num_calls++;
	} while (num_bytes != 0 && ret.error == SBI_SUCCESS);

	report_xfail(xfail, ret.error == SBI_SUCCESS, "write success (error=%ld)", ret.error);
	report_info("%d sbi calls made", num_calls);
}

static void dbcn_high_write_test(const char *s, unsigned long num_bytes,
				 phys_addr_t page_addr, size_t page_offset,
				 bool highmem_supported)
{
	int nr_pages = page_offset ? 2 : 1;
	void *vaddr;

	if (page_addr != PAGE_ALIGN(page_addr) || page_addr + PAGE_SIZE < HIGH_ADDR_BOUNDARY ||
	    !check_addr(page_addr, nr_pages * PAGE_SIZE)) {
		report_skip("Memory above 4G required");
		return;
	}

	vaddr = alloc_vpages(nr_pages);

	for (int i = 0; i < nr_pages; ++i)
		install_page(current_pgtable(), page_addr + i * PAGE_SIZE, vaddr + i * PAGE_SIZE);
	memcpy(vaddr + page_offset, DBCN_WRITE_TEST_STRING, num_bytes);
	dbcn_write_test(vaddr + page_offset, num_bytes, !highmem_supported);
}

/*
 * Only the write functionality is tested here. There's no easy way to
 * non-interactively test SBI_EXT_DBCN_CONSOLE_READ.
 */
static void check_dbcn(void)
{
	unsigned long num_bytes = strlen(DBCN_WRITE_TEST_STRING);
	unsigned long base_addr_lo, base_addr_hi;
	bool highmem_supported = true;
	phys_addr_t paddr;
	struct sbiret ret;
	char *buf;

	report_prefix_push("dbcn");

	if (!sbi_probe(SBI_EXT_DBCN)) {
		report_skip("DBCN extension unavailable");
		report_prefix_pop();
		return;
	}

	sbi_bad_fid(SBI_EXT_DBCN);

	report_prefix_push("write");

	dbcn_write_test(DBCN_WRITE_TEST_STRING, num_bytes, false);

	assert(num_bytes < PAGE_SIZE);

	report_prefix_push("page boundary");
	buf = alloc_pages(1);
	memcpy(&buf[PAGE_SIZE - num_bytes / 2], DBCN_WRITE_TEST_STRING, num_bytes);
	dbcn_write_test(&buf[PAGE_SIZE - num_bytes / 2], num_bytes, false);
	report_prefix_pop();

	if (env_enabled("SBI_HIGHMEM_NOT_SUPPORTED"))
		highmem_supported = false;

	report_prefix_push("high boundary");
	if (!env_enabled("SBI_DBCN_SKIP_HIGH_BOUNDARY"))
		dbcn_high_write_test(DBCN_WRITE_TEST_STRING, num_bytes,
				     HIGH_ADDR_BOUNDARY - PAGE_SIZE, PAGE_SIZE - num_bytes / 2,
				     highmem_supported);
	else
		report_skip("user disabled");
	report_prefix_pop();

	report_prefix_push("high page");
	if (!env_enabled("SBI_DBCN_SKIP_HIGH_PAGE")) {
		paddr = getenv("HIGH_PAGE") ? strtoull(getenv("HIGH_PAGE"), NULL, 0) : HIGH_ADDR_BOUNDARY;
		dbcn_high_write_test(DBCN_WRITE_TEST_STRING, num_bytes, paddr, 0, highmem_supported);
	} else {
		report_skip("user disabled");
	}
	report_prefix_pop();

	/* Bytes are read from memory and written to the console */
	report_prefix_push("invalid parameter");
	if (get_invalid_addr(&paddr, false)) {
		split_phys_addr(paddr, &base_addr_hi, &base_addr_lo);
		ret = sbi_dbcn_write(1, base_addr_lo, base_addr_hi);
		report(ret.error == SBI_ERR_INVALID_PARAM, "address (error=%ld)", ret.error);
	}
	report_prefix_popn(2);
	report_prefix_push("write_byte");

	puts("DBCN_WRITE_BYTE TEST BYTE: ");
	ret = sbi_dbcn_write_byte(DBCN_WRITE_BYTE_TEST_BYTE);
	puts("\n");
	report(ret.error == SBI_SUCCESS, "write success (error=%ld)", ret.error);
	report(ret.value == 0, "expected ret.value (%ld)", ret.value);

	puts("DBCN_WRITE_BYTE TEST WORD: "); /* still expect 'a' in the output */
	ret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, 0x64636261, 0, 0, 0, 0, 0);
	puts("\n");
	report(ret.error == SBI_SUCCESS, "write success (error=%ld)", ret.error);
	report(ret.value == 0, "expected ret.value (%ld)", ret.value);

	report_prefix_popn(2);
}

void sbi_susp_resume(unsigned long hartid, unsigned long opaque);
jmp_buf sbi_susp_jmp;

#define SBI_SUSP_TIMER_DURATION_US 500000
static void susp_timer(struct pt_regs *regs)
{
	timer_start(SBI_SUSP_TIMER_DURATION_US);
}

struct susp_params {
	unsigned long sleep_type;
	unsigned long resume_addr;
	unsigned long opaque;
	bool returns;
	struct sbiret ret;
};

static bool susp_basic_prep(unsigned long ctx[], struct susp_params *params)
{
	int cpu, me = smp_processor_id();
	unsigned long *csrs;
	struct sbiret ret;
	cpumask_t mask;

	csrs = (unsigned long *)ctx[SBI_SUSP_CSRS_IDX];
	csrs[SBI_CSR_SSTATUS_IDX] = csr_read(CSR_SSTATUS);
	csrs[SBI_CSR_SIE_IDX] = csr_read(CSR_SIE);
	csrs[SBI_CSR_STVEC_IDX] = csr_read(CSR_STVEC);
	csrs[SBI_CSR_SSCRATCH_IDX] = csr_read(CSR_SSCRATCH);
	csrs[SBI_CSR_SATP_IDX] = csr_read(CSR_SATP);

	memset(params, 0, sizeof(*params));
	params->sleep_type = 0; /* suspend-to-ram */
	params->resume_addr = virt_to_phys(sbi_susp_resume);
	params->opaque = virt_to_phys(ctx);
	params->returns = false;

	cpumask_copy(&mask, &cpu_present_mask);
	cpumask_clear_cpu(me, &mask);
	on_cpumask_async(&mask, stop_cpu, NULL);

	/* Wait up to 1s for all harts to stop */
	for (int i = 0; i < 100; i++) {
		int count = 1;

		udelay(10000);

		for_each_present_cpu(cpu) {
			if (cpu == me)
				continue;
			ret = sbi_hart_get_status(cpus[cpu].hartid);
			if (!ret.error && ret.value == SBI_EXT_HSM_STOPPED)
				++count;
		}
		if (count == cpumask_weight(&cpu_present_mask))
			break;
	}

	for_each_present_cpu(cpu) {
		ret = sbi_hart_get_status(cpus[cpu].hartid);
		if (cpu == me) {
			assert_msg(!ret.error && ret.value == SBI_EXT_HSM_STARTED,
				   "cpu%d is not started", cpu);
		} else {
			assert_msg(!ret.error && ret.value == SBI_EXT_HSM_STOPPED,
				   "cpu%d is not stopped", cpu);
		}
	}

	return true;
}

static void susp_basic_check(unsigned long ctx[], struct susp_params *params)
{
	if (ctx[SBI_SUSP_RESULTS_IDX] == SBI_SUSP_TEST_MASK) {
		report_pass("suspend and resume");
	} else {
		if (!(ctx[SBI_SUSP_RESULTS_IDX] & SBI_SUSP_TEST_SATP))
			report_fail("SATP set to zero on resume");
		if (!(ctx[SBI_SUSP_RESULTS_IDX] & SBI_SUSP_TEST_SIE))
			report_fail("sstatus.SIE clear on resume");
		if (!(ctx[SBI_SUSP_RESULTS_IDX] & SBI_SUSP_TEST_HARTID))
			report_fail("a0 is hartid on resume");
	}
}

static bool susp_type_prep(unsigned long ctx[], struct susp_params *params)
{
	bool r;

	r = susp_basic_prep(ctx, params);
	assert(r);
	params->sleep_type = 1;
	params->returns = true;
	params->ret.error = SBI_ERR_INVALID_PARAM;

	return true;
}

#if __riscv_xlen != 32
static bool susp_type_prep2(unsigned long ctx[], struct susp_params *params)
{
	bool r;

	r = susp_basic_prep(ctx, params);
	assert(r);
	params->sleep_type = BIT(32);

	return true;
}
#endif

static bool susp_badaddr_prep(unsigned long ctx[], struct susp_params *params)
{
	phys_addr_t badaddr;
	bool r;

	if (!get_invalid_addr(&badaddr, false))
		return false;

	r = susp_basic_prep(ctx, params);
	assert(r);
	params->resume_addr = badaddr;
	params->returns = true;
	params->ret.error = SBI_ERR_INVALID_ADDRESS;

	return true;
}

static bool susp_one_prep(unsigned long ctx[], struct susp_params *params)
{
	int started = 0, cpu, me = smp_processor_id();
	struct sbiret ret;
	bool r;

	if (cpumask_weight(&cpu_present_mask) < 2) {
		report_skip("At least 2 cpus required");
		return false;
	}

	r = susp_basic_prep(ctx, params);
	assert(r);
	params->returns = true;
	params->ret.error = SBI_ERR_DENIED;

	for_each_present_cpu(cpu) {
		if (cpu == me)
			continue;
		break;
	}

	on_cpu(cpu, start_cpu, NULL);

	for_each_present_cpu(cpu) {
		ret = sbi_hart_get_status(cpus[cpu].hartid);
		assert_msg(!ret.error, "HSM get status failed for cpu%d", cpu);
		if (ret.value == SBI_EXT_HSM_STARTED)
			started++;
	}

	assert(started == 2);

	return true;
}

static void check_susp(void)
{
	unsigned long csrs[SBI_CSR_NR_IDX];
	unsigned long ctx[SBI_SUSP_NR_IDX] = {
		[SBI_SUSP_MAGIC_IDX] = SBI_SUSP_MAGIC,
		[SBI_SUSP_CSRS_IDX] = (unsigned long)csrs,
		[SBI_SUSP_HARTID_IDX] = current_thread_info()->hartid,
	};
	enum {
#define SUSP_FIRST_TESTNUM 1
		SUSP_BASIC = SUSP_FIRST_TESTNUM,
		SUSP_TYPE,
		SUSP_TYPE2,
		SUSP_BAD_ADDR,
		SUSP_ONE_ONLINE,
		NR_SUSP_TESTS,
	};
	struct susp_test {
		const char *name;
		bool (*prep)(unsigned long ctx[], struct susp_params *params);
		void (*check)(unsigned long ctx[], struct susp_params *params);
	} susp_tests[] = {
		[SUSP_BASIC]		= { "basic",			susp_basic_prep,	susp_basic_check,	},
		[SUSP_TYPE]		= { "sleep_type",		susp_type_prep,					},
#if __riscv_xlen != 32
		[SUSP_TYPE2]		= { "sleep_type upper bits",	susp_type_prep2,	susp_basic_check	},
#endif
		[SUSP_BAD_ADDR]		= { "bad addr",			susp_badaddr_prep,				},
		[SUSP_ONE_ONLINE]	= { "one cpu online",		susp_one_prep,					},
	};
	struct susp_params params;
	struct sbiret ret;
	int testnum, i;

	report_prefix_push("susp");

	if (!sbi_probe(SBI_EXT_SUSP)) {
		report_skip("SUSP extension not available");
		report_prefix_pop();
		return;
	}

	sbi_bad_fid(SBI_EXT_SUSP);

	timer_setup(susp_timer);
	local_irq_enable();
	timer_start(SBI_SUSP_TIMER_DURATION_US);

	ret = sbi_ecall(SBI_EXT_SUSP, 1, 0, 0, 0, 0, 0, 0);
	report(ret.error == SBI_ERR_NOT_SUPPORTED, "funcid != 0 not supported");

	for (i = SUSP_FIRST_TESTNUM; i < NR_SUSP_TESTS; i++) {
		if (!susp_tests[i].name)
			continue;

		report_prefix_push(susp_tests[i].name);

		ctx[SBI_SUSP_TESTNUM_IDX] = i;
		ctx[SBI_SUSP_RESULTS_IDX] = 0;

		local_irq_disable();

		assert(susp_tests[i].prep);
		if (!susp_tests[i].prep(ctx, &params)) {
			report_prefix_pop();
			continue;
		}

		if ((testnum = setjmp(sbi_susp_jmp)) == 0) {
			ret = sbi_system_suspend_raw(params.sleep_type, params.resume_addr, params.opaque);

			local_irq_enable();

			if (!params.returns && ret.error == SBI_ERR_NOT_SUPPORTED) {
				report_fail("probing claims support, but it's not?");
				report_prefix_pop();
				goto out;
			} else if (!params.returns) {
				report_fail("unexpected return with error: %ld, value: %ld", ret.error, ret.value);
			} else {
				if (!report(ret.error == params.ret.error, "got expected sbi.error (%ld)", params.ret.error))
					report_info("expected sbi.error %ld, received %ld", params.ret.error, ret.error);
			}

			report_prefix_pop();
			continue;
		}
		assert(testnum == i);

		local_irq_enable();

		if (susp_tests[i].check)
			susp_tests[i].check(ctx, &params);

		report_prefix_pop();
	}

out:
	local_irq_disable();
	timer_teardown();

	report_prefix_pop();
}

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "-h")) {
		help();
		exit(0);
	}

	report_prefix_push("sbi");
	check_base();
	check_time();
	check_ipi();
	check_hsm();
	check_dbcn();
	check_susp();
	check_sse();
	check_fwft();

	return report_summary();
}
