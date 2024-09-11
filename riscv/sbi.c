// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc_page.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <vmalloc.h>
#include <memregions.h>
#include <asm/barrier.h>
#include <asm/csr.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <asm/mmu.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/timer.h>

#define	HIGH_ADDR_BOUNDARY	((phys_addr_t)1 << 32)

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

	ret = sbi_base(SBI_EXT_BASE_GET_SPEC_VERSION, 0);
	if (ret.error || ret.value < 2) {
		report_skip("SBI spec version 0.2 or higher required");
		return;
	}

	report_prefix_push("spec_version");
	if (env_or_skip("SBI_SPEC_VERSION")) {
		expected = (long)strtoul(getenv("SBI_SPEC_VERSION"), NULL, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

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
	bool do_invalid_addr = false;
	bool highmem_supported = true;
	phys_addr_t paddr;
	struct sbiret ret;
	const char *tmp;
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

	tmp = getenv("SBI_HIGHMEM_NOT_SUPPORTED");
	if (tmp && atol(tmp) != 0)
		highmem_supported = false;

	report_prefix_push("high boundary");
	tmp = getenv("SBI_DBCN_SKIP_HIGH_BOUNDARY");
	if (!tmp || atol(tmp) == 0)
		dbcn_high_write_test(DBCN_WRITE_TEST_STRING, num_bytes,
				     HIGH_ADDR_BOUNDARY - PAGE_SIZE, PAGE_SIZE - num_bytes / 2,
				     highmem_supported);
	else
		report_skip("user disabled");
	report_prefix_pop();

	report_prefix_push("high page");
	tmp = getenv("SBI_DBCN_SKIP_HIGH_PAGE");
	if (!tmp || atol(tmp) == 0) {
		paddr = HIGH_ADDR_BOUNDARY;
		tmp = getenv("HIGH_PAGE");
		if (tmp)
			paddr = strtoull(tmp, NULL, 0);
		dbcn_high_write_test(DBCN_WRITE_TEST_STRING, num_bytes, paddr, 0, highmem_supported);
	} else {
		report_skip("user disabled");
	}
	report_prefix_pop();

	/* Bytes are read from memory and written to the console */
	report_prefix_push("invalid parameter");
	tmp = getenv("INVALID_ADDR_AUTO");
	if (tmp && atol(tmp) == 1) {
		paddr = get_highest_addr() + 1;
		do_invalid_addr = true;
	} else if (env_or_skip("INVALID_ADDR")) {
		paddr = strtoull(getenv("INVALID_ADDR"), NULL, 0);
		do_invalid_addr = true;
	}

	if (do_invalid_addr) {
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
