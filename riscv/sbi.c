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
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/timer.h>

#include "sbi-tests.h"

#define	HIGH_ADDR_BOUNDARY	((phys_addr_t)1 << 32)

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

static struct sbiret sbi_system_suspend(uint32_t sleep_type, unsigned long resume_addr, unsigned long opaque)
{
	return sbi_ecall(SBI_EXT_SUSP, 0, sleep_type, resume_addr, opaque, 0, 0, 0);
}

static void start_cpu(void *data)
{
	/* nothing to do */
}

static void stop_cpu(void *data)
{
	struct sbiret ret = sbi_hart_stop();
	assert_msg(0, "cpu%d failed to stop with sbiret.error %ld", smp_processor_id(), ret.error);
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

static bool env_enabled(const char *env)
{
	char *s = getenv(env);

	return s && (*s == '1' || *s == 'y' || *s == 'Y');
}

static bool env_or_skip(const char *env)
{
	if (!getenv(env)) {
		report_skip("missing %s environment variable", env);
		return false;
	}

	return true;
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

static void gen_report(struct sbiret *ret,
		       long expected_error, long expected_value)
{
	bool check_error = ret->error == expected_error;
	bool check_value = ret->value == expected_value;

	if (!check_error || !check_value)
		report_info("expected (error: %ld, value: %ld), received: (error: %ld, value %ld)",
			    expected_error, expected_value, ret->error, ret->value);

	report(check_error, "expected sbi.error");
	report(check_value, "expected sbi.value");
}

static void check_base(void)
{
	struct sbiret ret;
	long expected;

	report_prefix_push("base");

	ret = sbi_base(SBI_EXT_BASE_GET_SPEC_VERSION, 0);

	report_prefix_push("spec_version");
	if (env_or_skip("SBI_SPEC_VERSION")) {
		expected = (long)strtoul(getenv("SBI_SPEC_VERSION"), NULL, 0);
		assert_msg(!(expected & BIT(31)), "SBI spec version bit 31 must be zero");
		assert_msg(__riscv_xlen == 32 || !(expected >> 32), "SBI spec version bits greater than 31 must be zero");
		gen_report(&ret, 0, expected);
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
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("impl_version");
	if (env_or_skip("SBI_IMPL_VERSION")) {
		expected = (long)strtoul(getenv("SBI_IMPL_VERSION"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_IMP_VERSION, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("probe_ext");
	expected = getenv("SBI_PROBE_EXT") ? (long)strtoul(getenv("SBI_PROBE_EXT"), NULL, 0) : 1;
	ret = sbi_base(SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE);
	gen_report(&ret, 0, expected);
	report_prefix_push("unavailable");
	ret = sbi_base(SBI_EXT_BASE_PROBE_EXT, 0xb000000);
	gen_report(&ret, 0, 0);
	report_prefix_popn(2);

	report_prefix_push("mvendorid");
	if (env_or_skip("MVENDORID")) {
		expected = (long)strtoul(getenv("MVENDORID"), NULL, 0);
		assert(__riscv_xlen == 32 || !(expected >> 32));
		ret = sbi_base(SBI_EXT_BASE_GET_MVENDORID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("marchid");
	if (env_or_skip("MARCHID")) {
		expected = (long)strtoul(getenv("MARCHID"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_MARCHID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("mimpid");
	if (env_or_skip("MIMPID")) {
		expected = (long)strtoul(getenv("MIMPID"), NULL, 0);
		ret = sbi_base(SBI_EXT_BASE_GET_MIMPID, 0);
		gen_report(&ret, 0, expected);
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

	/* Try the next higher hartid than the max */
	ret = sbi_send_ipi(2, max_hartid);
	report_kfail(true, ret.error == SBI_ERR_INVALID_PARAM, "hart_mask got expected error (%ld)", ret.error);
	ret = sbi_send_ipi(1, max_hartid + 1);
	report_kfail(true, ret.error == SBI_ERR_INVALID_PARAM, "hart_mask_base got expected error (%ld)", ret.error);

	report_prefix_pop();

	report_prefix_pop();
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
	struct sbiret ret;
	cpumask_t mask;

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
	unsigned long csrs[] = {
		[SBI_CSR_SSTATUS_IDX] = csr_read(CSR_SSTATUS),
		[SBI_CSR_SIE_IDX] = csr_read(CSR_SIE),
		[SBI_CSR_STVEC_IDX] = csr_read(CSR_STVEC),
		[SBI_CSR_SSCRATCH_IDX] = csr_read(CSR_SSCRATCH),
		[SBI_CSR_SATP_IDX] = csr_read(CSR_SATP),
	};
	unsigned long ctx[] = {
		[SBI_SUSP_MAGIC_IDX] = SBI_SUSP_MAGIC,
		[SBI_SUSP_CSRS_IDX] = (unsigned long)csrs,
		[SBI_SUSP_HARTID_IDX] = current_thread_info()->hartid,
		[SBI_SUSP_TESTNUM_IDX] = 0,
		[SBI_SUSP_RESULTS_IDX] = 0,
	};
	enum {
#define SUSP_FIRST_TESTNUM 1
		SUSP_BASIC = SUSP_FIRST_TESTNUM,
		SUSP_TYPE,
		SUSP_BAD_ADDR,
		SUSP_ONE_ONLINE,
		NR_SUSP_TESTS,
	};
	struct susp_test {
		const char *name;
		bool (*prep)(unsigned long ctx[], struct susp_params *params);
		void (*check)(unsigned long ctx[], struct susp_params *params);
	} susp_tests[] = {
		[SUSP_BASIC]		= { "basic",		susp_basic_prep,	susp_basic_check,	},
		[SUSP_TYPE]		= { "sleep_type",	susp_type_prep,					},
		[SUSP_BAD_ADDR]		= { "bad addr",		susp_badaddr_prep,				},
		[SUSP_ONE_ONLINE]	= { "one cpu online",	susp_one_prep,					},
	};
	struct susp_params params;
	struct sbiret ret;
	int testnum, i;

	local_irq_disable();
	timer_stop();

	report_prefix_push("susp");

	ret = sbi_ecall(SBI_EXT_SUSP, 1, 0, 0, 0, 0, 0, 0);
	report(ret.error == SBI_ERR_NOT_SUPPORTED, "funcid != 0 not supported");

	for (i = SUSP_FIRST_TESTNUM; i < NR_SUSP_TESTS; i++) {
		report_prefix_push(susp_tests[i].name);

		ctx[SBI_SUSP_TESTNUM_IDX] = i;
		ctx[SBI_SUSP_RESULTS_IDX] = 0;

		assert(susp_tests[i].prep);
		if (!susp_tests[i].prep(ctx, &params)) {
			report_prefix_pop();
			continue;
		}

		if ((testnum = setjmp(sbi_susp_jmp)) == 0) {
			ret = sbi_system_suspend(params.sleep_type, params.resume_addr, params.opaque);

			if (!params.returns && ret.error == SBI_ERR_NOT_SUPPORTED) {
				report_skip("SUSP not supported?");
				report_prefix_popn(2);
				return;
			} else if (!params.returns) {
				report_fail("unexpected return with error: %ld, value: %ld", ret.error, ret.value);
			} else {
				report(ret.error == params.ret.error, "expected sbi.error");
				if (ret.error != params.ret.error)
					report_info("expected error %ld, received %ld", params.ret.error, ret.error);
			}

			report_prefix_pop();
			continue;
		}
		assert(testnum == i);

		if (susp_tests[i].check)
			susp_tests[i].check(ctx, &params);

		report_prefix_pop();
	}

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
	check_dbcn();
	check_susp();

	return report_summary();
}
