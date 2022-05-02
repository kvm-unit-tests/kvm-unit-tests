/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Storage key tests
 *
 * Copyright (c) 2018 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.vnet.ibm.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <vmalloc.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/mem.h>


static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));

static void test_set_mb(void)
{
	union skey skey, ret1, ret2;
	void *addr = (void *)0x10000 - 2 * PAGE_SIZE;
	void *end = (void *)0x10000;

	/* Multi block support came with EDAT 1 */
	if (!test_facility(8))
		return;

	skey.val = 0x30;
	while (addr < end)
		addr = set_storage_key_mb(addr, skey.val);

	ret1.val = get_storage_key(end - PAGE_SIZE) & (SKEY_ACC | SKEY_FP);
	ret2.val = get_storage_key(end - PAGE_SIZE * 2) & (SKEY_ACC | SKEY_FP);
	report(ret1.val == ret2.val && ret1.val == skey.val, "multi block");
}

static void test_chg(void)
{
	union skey skey1, skey2;

	skey1.val = 0x30;
	set_storage_key(pagebuf, skey1.val, 0);
	skey1.val = get_storage_key(pagebuf);
	pagebuf[0] = 3;
	skey2.val = get_storage_key(pagebuf);
	report(!skey1.str.ch && skey2.str.ch, "chg bit test");
}

static void test_set(void)
{
	union skey skey, ret;

	skey.val = 0x30;
	ret.val = get_storage_key(pagebuf);
	set_storage_key(pagebuf, skey.val, 0);
	ret.val = get_storage_key(pagebuf);
	/*
	 * For all set tests we only test the ACC and FP bits. RF and
	 * CH are set by the machine for memory references and changes
	 * and hence might change between a set and a get.
	 */
	report(skey.str.acc == ret.str.acc && skey.str.fp == ret.str.fp,
	       "set key test");
}

static void test_priv(void)
{
	union skey skey;

	memset(pagebuf, 0, PAGE_SIZE * 2);
	report_prefix_push("privileged");
	report_prefix_push("sske");
	expect_pgm_int();
	enter_pstate();
	set_storage_key(pagebuf, 0x30, 0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	skey.val = get_storage_key(pagebuf);
	report(skey.str.acc != 3, "skey did not change on exception");

	report_prefix_push("iske");
	expect_pgm_int();
	enter_pstate();
	get_storage_key(pagebuf);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	report_prefix_pop();
}

static void test_invalid_address(void)
{
	void *inv_addr = (void *)-1ull;

	report_prefix_push("invalid address");

	report_prefix_push("sske");
	expect_pgm_int();
	set_storage_key(inv_addr, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
	report_prefix_pop();

	report_prefix_push("iske");
	expect_pgm_int();
	get_storage_key(inv_addr);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
	report_prefix_pop();

	report_prefix_push("rrbe");
	expect_pgm_int();
	reset_reference_bit(inv_addr);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
	report_prefix_pop();

	report_prefix_pop();
}

static void test_test_protection(void)
{
	unsigned long addr = (unsigned long)pagebuf;

	report_prefix_push("TPROT");

	set_storage_key(pagebuf, 0x10, 0);
	report(tprot(addr, 0) == TPROT_READ_WRITE, "zero key: no protection");
	report(tprot(addr, 1) == TPROT_READ_WRITE, "matching key: no protection");

	report_prefix_push("mismatching key");

	report(tprot(addr, 2) == TPROT_READ, "no fetch protection: store protection");

	set_storage_key(pagebuf, 0x18, 0);
	report(tprot(addr, 2) == TPROT_RW_PROTECTED,
	       "fetch protection: fetch & store protection");

	report_prefix_push("fetch-protection override");
	set_storage_key(0, 0x18, 0);
	report(tprot(0, 2) == TPROT_RW_PROTECTED, "disabled: fetch & store protection");
	ctl_set_bit(0, CTL0_FETCH_PROTECTION_OVERRIDE);
	report(tprot(0, 2) == TPROT_READ, "enabled: store protection");
	report(tprot(2048, 2) == TPROT_RW_PROTECTED, "invalid: fetch & store protection");
	ctl_clear_bit(0, CTL0_FETCH_PROTECTION_OVERRIDE);
	set_storage_key(0, 0x00, 0);
	report_prefix_pop();

	ctl_set_bit(0, CTL0_STORAGE_PROTECTION_OVERRIDE);
	set_storage_key(pagebuf, 0x90, 0);
	report(tprot(addr, 2) == TPROT_READ_WRITE,
	       "storage-protection override: no protection");
	ctl_clear_bit(0, CTL0_STORAGE_PROTECTION_OVERRIDE);

	report_prefix_pop();
	set_storage_key(pagebuf, 0x00, 0);
	report_prefix_pop();
}

/*
 * Perform STORE CPU ADDRESS (STAP) instruction while temporarily executing
 * with access key 1.
 */
static void store_cpu_address_key_1(uint16_t *out)
{
	asm volatile (
		"spka	0x10\n\t"
		"stap	%0\n\t"
		"spka	0\n"
	     : "+Q" (*out) /* exception: old value remains in out -> + constraint */
	);
}

static void test_store_cpu_address(void)
{
	uint16_t *out = (uint16_t *)pagebuf;
	uint16_t cpu_addr;

	report_prefix_push("STORE CPU ADDRESS");
	asm ("stap %0" : "=Q" (cpu_addr));

	report_prefix_push("zero key");
	set_storage_key(pagebuf, 0x20, 0);
	WRITE_ONCE(*out, 0xbeef);
	asm ("stap %0" : "=Q" (*out));
	report(*out == cpu_addr, "store occurred");
	report_prefix_pop();

	report_prefix_push("matching key");
	set_storage_key(pagebuf, 0x10, 0);
	*out = 0xbeef;
	store_cpu_address_key_1(out);
	report(*out == cpu_addr, "store occurred");
	report_prefix_pop();

	report_prefix_push("mismatching key");
	set_storage_key(pagebuf, 0x20, 0);
	expect_pgm_int();
	*out = 0xbeef;
	store_cpu_address_key_1(out);
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report(*out == 0xbeef, "no store occurred");
	report_prefix_pop();

	ctl_set_bit(0, CTL0_STORAGE_PROTECTION_OVERRIDE);

	report_prefix_push("storage-protection override, invalid key");
	set_storage_key(pagebuf, 0x20, 0);
	expect_pgm_int();
	*out = 0xbeef;
	store_cpu_address_key_1(out);
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report(*out == 0xbeef, "no store occurred");
	report_prefix_pop();

	report_prefix_push("storage-protection override, override key");
	set_storage_key(pagebuf, 0x90, 0);
	*out = 0xbeef;
	store_cpu_address_key_1(out);
	report(*out == cpu_addr, "override occurred");
	report_prefix_pop();

	ctl_clear_bit(0, CTL0_STORAGE_PROTECTION_OVERRIDE);

	report_prefix_push("storage-protection override disabled, override key");
	set_storage_key(pagebuf, 0x90, 0);
	expect_pgm_int();
	*out = 0xbeef;
	store_cpu_address_key_1(out);
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report(*out == 0xbeef, "no store occurred");
	report_prefix_pop();

	set_storage_key(pagebuf, 0x00, 0);
	report_prefix_pop();
}

/*
 * Perform SET PREFIX (SPX) instruction while temporarily executing
 * with access key 1.
 */
static void set_prefix_key_1(uint32_t *prefix_ptr)
{
	asm volatile (
		"spka	0x10\n\t"
		"spx	%0\n\t"
		"spka	0\n"
	     :: "Q" (*prefix_ptr)
	);
}

/*
 * We remapped page 0, making the lowcore inaccessible, which breaks the normal
 * handler and breaks skipping the faulting instruction.
 * Just disable dynamic address translation to make things work.
 */
static void dat_fixup_pgm_int(void)
{
	uint64_t psw_mask = extract_psw_mask();

	psw_mask &= ~PSW_MASK_DAT;
	load_psw_mask(psw_mask);
}

#define PREFIX_AREA_SIZE (PAGE_SIZE * 2)
static char lowcore_tmp[PREFIX_AREA_SIZE] __attribute__((aligned(PREFIX_AREA_SIZE)));

/*
 * Test accessibility of the operand to SET PREFIX given different configurations
 * with regards to storage keys. That is, check the accessibility of the location
 * holding the new prefix, not that of the new prefix area. The new prefix area
 * is a valid lowcore, so that the test does not crash on failure.
 */
static void test_set_prefix(void)
{
	uint32_t *prefix_ptr = (uint32_t *)pagebuf;
	uint32_t *no_override_prefix_ptr;
	uint32_t old_prefix;
	pgd_t *root;

	report_prefix_push("SET PREFIX");
	root = (pgd_t *)(stctg(1) & PAGE_MASK);
	old_prefix = get_prefix();
	memcpy(lowcore_tmp, 0, sizeof(lowcore_tmp));
	assert(((uint64_t)&lowcore_tmp >> 31) == 0);
	*prefix_ptr = (uint32_t)(uint64_t)&lowcore_tmp;

	report_prefix_push("zero key");
	set_prefix(old_prefix);
	set_storage_key(prefix_ptr, 0x20, 0);
	set_prefix(*prefix_ptr);
	report(get_prefix() == *prefix_ptr, "set prefix");
	report_prefix_pop();

	report_prefix_push("matching key");
	set_prefix(old_prefix);
	set_storage_key(pagebuf, 0x10, 0);
	set_prefix_key_1(prefix_ptr);
	report(get_prefix() == *prefix_ptr, "set prefix");
	report_prefix_pop();

	report_prefix_push("mismatching key");

	report_prefix_push("no fetch protection");
	set_prefix(old_prefix);
	set_storage_key(pagebuf, 0x20, 0);
	set_prefix_key_1(prefix_ptr);
	report(get_prefix() == *prefix_ptr, "set prefix");
	report_prefix_pop();

	report_prefix_push("fetch protection");
	set_prefix(old_prefix);
	set_storage_key(pagebuf, 0x28, 0);
	expect_pgm_int();
	set_prefix_key_1(prefix_ptr);
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report(get_prefix() == old_prefix, "did not set prefix");
	report_prefix_pop();

	register_pgm_cleanup_func(dat_fixup_pgm_int);

	report_prefix_push("remapped page, fetch protection");
	set_prefix(old_prefix);
	set_storage_key(pagebuf, 0x28, 0);
	expect_pgm_int();
	install_page(root, virt_to_pte_phys(root, pagebuf), 0);
	set_prefix_key_1((uint32_t *)0);
	install_page(root, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report(get_prefix() == old_prefix, "did not set prefix");
	report_prefix_pop();

	ctl_set_bit(0, CTL0_FETCH_PROTECTION_OVERRIDE);

	report_prefix_push("fetch protection override applies");
	set_prefix(old_prefix);
	set_storage_key(pagebuf, 0x28, 0);
	install_page(root, virt_to_pte_phys(root, pagebuf), 0);
	set_prefix_key_1((uint32_t *)0);
	install_page(root, 0, 0);
	report(get_prefix() == *prefix_ptr, "set prefix");
	report_prefix_pop();

	no_override_prefix_ptr = (uint32_t *)(pagebuf + 2048);
	WRITE_ONCE(*no_override_prefix_ptr, (uint32_t)(uint64_t)&lowcore_tmp);
	report_prefix_push("fetch protection override does not apply");
	set_prefix(old_prefix);
	set_storage_key(pagebuf, 0x28, 0);
	expect_pgm_int();
	install_page(root, virt_to_pte_phys(root, pagebuf), 0);
	set_prefix_key_1((uint32_t *)2048);
	install_page(root, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report(get_prefix() == old_prefix, "did not set prefix");
	report_prefix_pop();

	ctl_clear_bit(0, CTL0_FETCH_PROTECTION_OVERRIDE);
	register_pgm_cleanup_func(NULL);
	report_prefix_pop();
	set_storage_key(pagebuf, 0x00, 0);
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("skey");
	if (test_facility(169)) {
		report_skip("storage key removal facility is active");
		goto done;
	}
	test_priv();
	test_invalid_address();
	test_set();
	test_set_mb();
	test_chg();
	test_test_protection();
	test_store_cpu_address();

	setup_vm();
	test_set_prefix();
done:
	report_prefix_pop();
	return report_summary();
}
