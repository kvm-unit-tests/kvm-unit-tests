// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <stdlib.h>
#include <limits.h>
#include <asm/barrier.h>
#include <asm/csr.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <asm/isa.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/timer.h>

static void help(void)
{
	puts("Test SBI\n");
	puts("An environ must be provided where expected values are given.\n");
}

static struct sbiret __base_sbi_ecall(int fid, unsigned long arg0)
{
	return sbi_ecall(SBI_EXT_BASE, fid, arg0, 0, 0, 0, 0, 0);
}

static struct sbiret __time_sbi_ecall(unsigned long stime_value)
{
	return sbi_ecall(SBI_EXT_TIME, SBI_EXT_TIME_SET_TIMER, stime_value, 0, 0, 0, 0, 0);
}

static struct sbiret __dbcn_sbi_ecall(int fid, unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	return sbi_ecall(SBI_EXT_DBCN, fid, arg0, arg1, arg2, 0, 0, 0);
}

static void split_phys_addr(phys_addr_t paddr, unsigned long *hi, unsigned long *lo)
{
	*lo = (unsigned long)paddr;
	*hi = 0;
	if (__riscv_xlen == 32)
		*hi = (unsigned long)(paddr >> 32);
}

static bool env_or_skip(const char *env)
{
	if (!getenv(env)) {
		report_skip("missing %s environment variable", env);
		return false;
	}

	return true;
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

	ret = __base_sbi_ecall(SBI_EXT_BASE_GET_SPEC_VERSION, 0);
	if (ret.error || ret.value < 2) {
		report_skip("SBI spec version 0.2 or higher required");
		return;
	}

	report_prefix_push("spec_version");
	if (env_or_skip("SPEC_VERSION")) {
		expected = strtol(getenv("SPEC_VERSION"), NULL, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("impl_id");
	if (env_or_skip("IMPL_ID")) {
		expected = strtol(getenv("IMPL_ID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_IMP_ID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("impl_version");
	if (env_or_skip("IMPL_VERSION")) {
		expected = strtol(getenv("IMPL_VERSION"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_IMP_VERSION, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("probe_ext");
	expected = getenv("PROBE_EXT") ? strtol(getenv("PROBE_EXT"), NULL, 0) : 1;
	ret = __base_sbi_ecall(SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE);
	gen_report(&ret, 0, expected);
	report_prefix_push("unavailable");
	ret = __base_sbi_ecall(SBI_EXT_BASE_PROBE_EXT, 0xb000000);
	gen_report(&ret, 0, 0);
	report_prefix_pop();
	report_prefix_pop();

	report_prefix_push("mvendorid");
	if (env_or_skip("MVENDORID")) {
		expected = strtol(getenv("MVENDORID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MVENDORID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("marchid");
	if (env_or_skip("MARCHID")) {
		expected = strtol(getenv("MARCHID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MARCHID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("mimpid");
	if (env_or_skip("MIMPID")) {
		expected = strtol(getenv("MIMPID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MIMPID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_pop();
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
		__time_sbi_ecall(ULONG_MAX);

	if (!timer_irq_pending())
		timer_info.timer_irq_cleared = true;
}

static void timer_check_set_timer(bool mask_timer_irq)
{
	struct sbiret ret;
	unsigned long begin, end, duration;
	const char *mask_test_str = mask_timer_irq ? " for mask irq test" : "";
	unsigned long d = getenv("TIMER_DELAY") ? strtol(getenv("TIMER_DELAY"), NULL, 0) : 200000;
	unsigned long margin = getenv("TIMER_MARGIN") ? strtol(getenv("TIMER_MARGIN"), NULL, 0) : 200000;

	d = usec_to_cycles(d);
	margin = usec_to_cycles(margin);

	timer_info = (struct timer_info){ .mask_timer_irq = mask_timer_irq };
	begin = timer_get_cycles();
	ret = __time_sbi_ecall(begin + d);

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
	if (cpu_has_extension(smp_processor_id(), ISA_SSTC)) {
		csr_write(CSR_STIMECMP, ULONG_MAX);
		if (__riscv_xlen == 32)
			csr_write(CSR_STIMECMPH, ULONG_MAX);
	}
	timer_irq_enable();

	timer_check_set_timer(false);

	if (csr_read(CSR_SIE) & IE_TIE)
		timer_check_set_timer(true);
	else
		report_skip("timer irq enable bit is not writable, skipping mask irq test");

	timer_irq_disable();
	__time_sbi_ecall(0);
	pending = timer_irq_pending();
	report(pending, "timer immediately pending by setting timer to 0");
	__time_sbi_ecall(ULONG_MAX);
	if (pending)
		report(!timer_irq_pending(), "pending timer cleared while masked");
	else
		report_skip("timer is not pending, skipping timer cleared while masked test");

	local_irq_disable();
	install_irq_handler(IRQ_S_TIMER, NULL);

	report_prefix_pop();
	report_prefix_pop();
}

#define DBCN_WRITE_TEST_STRING		"DBCN_WRITE_TEST_STRING\n"
#define DBCN_WRITE_BYTE_TEST_BYTE	(u8)'a'

/*
 * Only the write functionality is tested here. There's no easy way to
 * non-interactively test the read functionality.
 */
static void check_dbcn(void)
{
	unsigned long num_bytes, base_addr_lo, base_addr_hi;
	phys_addr_t paddr;
	int num_calls = 0;
	struct sbiret ret;

	report_prefix_push("dbcn");

	ret = __base_sbi_ecall(SBI_EXT_BASE_PROBE_EXT, SBI_EXT_DBCN);
	if (!ret.value) {
		report_skip("DBCN extension unavailable");
		report_prefix_pop();
		return;
	}

	num_bytes = strlen(DBCN_WRITE_TEST_STRING);
	paddr = virt_to_phys((void *)&DBCN_WRITE_TEST_STRING);
	split_phys_addr(paddr, &base_addr_hi, &base_addr_lo);

	report_prefix_push("write");

	do {
		ret = __dbcn_sbi_ecall(SBI_EXT_DBCN_CONSOLE_WRITE, num_bytes, base_addr_lo, base_addr_hi);
		num_bytes -= ret.value;
		paddr += ret.value;
		split_phys_addr(paddr, &base_addr_hi, &base_addr_lo);
		num_calls++;
	} while (num_bytes != 0 && ret.error == SBI_SUCCESS);

	report(ret.error == SBI_SUCCESS, "write success (error=%ld)", ret.error);
	report_info("%d sbi calls made", num_calls);

	/* Bytes are read from memory and written to the console */
	if (env_or_skip("INVALID_ADDR")) {
		paddr = strtoull(getenv("INVALID_ADDR"), NULL, 0);
		split_phys_addr(paddr, &base_addr_hi, &base_addr_lo);
		ret = __dbcn_sbi_ecall(SBI_EXT_DBCN_CONSOLE_WRITE, 1, base_addr_lo, base_addr_hi);
		report(ret.error == SBI_ERR_INVALID_PARAM, "invalid parameter: address (error=%ld)", ret.error);
	}

	report_prefix_pop();

	report_prefix_push("write_byte");

	puts("DBCN_WRITE TEST CHAR: ");
	ret = __dbcn_sbi_ecall(SBI_EXT_DBCN_CONSOLE_WRITE_BYTE, (u8)DBCN_WRITE_BYTE_TEST_BYTE, 0, 0);
	puts("\n");
	report(ret.error == SBI_SUCCESS, "write success (error=%ld)", ret.error);
	report(ret.value == 0, "expected ret.value (%ld)", ret.value);

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
	check_dbcn();

	return report_summary();
}
