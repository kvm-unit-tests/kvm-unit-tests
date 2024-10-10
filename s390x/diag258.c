/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Diag 258: Async Page Fault Handler
 *
 * Copyright (c) 2024 IBM Corp
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */

#include <libcflat.h>
#include <asm-generic/barrier.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/mem.h>
#include <asm/pgtable.h>
#include <mmu.h>
#include <sclp.h>
#include <vmalloc.h>

static uint8_t prefix_buf[LC_SIZE] __attribute__((aligned(LC_SIZE)));

#define __PF_RES_FIELD 0x8000000000000000UL

/* copied from Linux arch/s390/mm/pfault.c */
struct pfault_refbk {
	u16 refdiagc;
	u16 reffcode;
	u16 refdwlen;
	u16 refversn;
	u64 refgaddr;
	u64 refselmk;
	u64 refcmpmk;
	u64 reserved;
};

uint64_t pfault_token = 0x0123fadec0fe3210UL;

static struct pfault_refbk pfault_init_refbk __attribute__((aligned(8))) = {
	.refdiagc = 0x258,
	.reffcode = 0, /* TOKEN */
	.refdwlen = sizeof(struct pfault_refbk) / sizeof(uint64_t),
	.refversn = 2,
	.refgaddr = (u64)&pfault_token,
	.refselmk = 1UL << 48,
	.refcmpmk = 1UL << 48,
	.reserved = __PF_RES_FIELD
};

static struct pfault_refbk pfault_cancel_refbk __attribute((aligned(8))) = {
	.refdiagc = 0x258,
	.reffcode = 1, /* CANCEL */
	.refdwlen = sizeof(struct pfault_refbk) / sizeof(uint64_t),
	.refversn = 2,
	.refgaddr = 0,
	.refselmk = 0,
	.refcmpmk = 0,
	.reserved = 0
};

static inline int diag258(struct pfault_refbk *refbk)
{
	int rc = -1;

	asm volatile(
		"	diag	%[refbk],%[rc],0x258\n"
		: [rc] "+d" (rc)
		: [refbk] "a" (refbk), "m" (*(refbk))
		: "cc");
	return rc;
}

static void test_priv(void)
{
	report_prefix_push("privileged");
	expect_pgm_int();
	enter_pstate();
	diag258(&pfault_init_refbk);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static void *page_map_outside_real_space(phys_addr_t page_real)
{
	pgd_t *root = (pgd_t *)(stctg(1) & PAGE_MASK);
	void *vaddr = alloc_vpage();

	install_page(root, page_real, vaddr);

	return vaddr;
}

/*
 * Verify that the refbk pointer is a real address and not a virtual
 * address. This is tested by enabling DAT and establishing a mapping
 * for the refbk that is outside of the bounds of our (guest-)physical
 * address space.
 */
static void test_refbk_real(void)
{
	struct pfault_refbk *refbk;
	void *refbk_page;
	pgd_t *root;

	report_prefix_push("refbk is real");

	/* Set up virtual memory and allocate a physical page for storing the refbk */
	setup_vm();
	refbk_page = alloc_page();

	/* Map refblk page outside of physical memory identity mapping */
	root = (pgd_t *)(stctg(1) & PAGE_MASK);
	refbk = page_map_outside_real_space(virt_to_pte_phys(root, refbk_page));

	/* Assert the mapping really is outside identity mapping */
	report_info("refbk is at 0x%lx", (u64)refbk);
	report_info("ram size is 0x%lx", get_ram_size());
	assert((u64)refbk > get_ram_size());

	/* Copy the init refbk to the page */
	memcpy(refbk, &pfault_init_refbk, sizeof(struct pfault_refbk));

	/* Protect the virtual mapping to avoid diag258 actually doing something */
	protect_page(refbk, PAGE_ENTRY_I);

	expect_pgm_int();
	diag258(refbk);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
	report_prefix_pop();

	free_page(refbk_page);
	disable_dat();
	irq_set_dat_mode(false, 0);
}

/*
 * Verify diag258 correctly applies prefixing.
 */
static void test_refbk_prefixing(void)
{
	const size_t lowcore_offset_for_refbk = offsetof(struct lowcore, pad_0x03a0);
	struct pfault_refbk *refbk_in_prefix, *refbk_in_reverse_prefix;
	uint32_t old_prefix;
	uint64_t ry;

	report_prefix_push("refbk prefixing");

	report_info("refbk at lowcore offset 0x%lx", lowcore_offset_for_refbk);

	assert((unsigned long)&prefix_buf < SZ_2G);

	memcpy(prefix_buf, 0, LC_SIZE);

	/*
	 * After the call to set_prefix() below, this will refer to absolute
	 * address lowcore_offset_for_refbk (reverse prefixing).
	 */
	refbk_in_reverse_prefix = (struct pfault_refbk *)(&prefix_buf[0] + lowcore_offset_for_refbk);

	/*
	 * After the call to set_prefix() below, this will refer to absolute
	 * address &prefix_buf[0] + lowcore_offset_for_refbk (forward prefixing).
	 */
	refbk_in_prefix = (struct pfault_refbk *)OPAQUE_PTR(lowcore_offset_for_refbk);

	old_prefix = get_prefix();
	set_prefix((uint32_t)(uintptr_t)prefix_buf);

	/*
	 * If diag258 would not be applying prefixing on access to
	 * refbk_in_reverse_prefix correctly, it would access absolute address
	 * refbk_in_reverse_prefix (which to us is accessible at real address
	 * refbk_in_prefix).
	 * Make sure it really fails by putting invalid function code
	 * at refbk_in_prefix.
	 */
	refbk_in_prefix->refdiagc = 0xc0fe;

	/*
	 * Put a valid refbk at refbk_in_reverse_prefix.
	 */
	memcpy(refbk_in_reverse_prefix, &pfault_init_refbk, sizeof(pfault_init_refbk));

	ry = diag258(refbk_in_reverse_prefix);
	report(!ry, "real address refbk accessed");

	/*
	 * Activating should have worked. Cancel the activation and expect
	 * return 0. If activation would not have worked, this should return with
	 * 4 (pfault handshaking not active).
	 */
	ry = diag258(&pfault_cancel_refbk);
	report(!ry, "handshaking canceled");

	set_prefix(old_prefix);

	report_prefix_pop();
}

/*
 * Verify that a refbk exceeding physical memory is not accepted, even
 * when crossing a frame boundary.
 */
static void test_refbk_crossing(void)
{
	const size_t bytes_in_last_page = 8;
	struct pfault_refbk *refbk = (struct pfault_refbk *)(get_ram_size() - bytes_in_last_page);

	report_prefix_push("refbk crossing");

	report_info("refbk is at 0x%lx", (u64)refbk);
	report_info("ram size is 0x%lx", get_ram_size());
	assert(sizeof(struct pfault_refbk) > bytes_in_last_page);

	/* Copy bytes_in_last_page bytes of the init refbk to the page */
	memcpy(refbk, &pfault_init_refbk, bytes_in_last_page);

	expect_pgm_int();
	diag258(refbk);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
	report_prefix_pop();
}

/*
 * Verify that a refbk with an invalid refdiagc is not accepted.
 */
static void test_refbk_invalid_diagcode(void)
{
	struct pfault_refbk refbk __attribute__((aligned(8))) = pfault_init_refbk;

	report_prefix_push("invalid refdiagc");
	refbk.refdiagc = 0xc0fe;

	expect_pgm_int();
	diag258(&refbk);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("diag258");

	expect_pgm_int();
	diag258((struct pfault_refbk *)0xfffffffffffffff0);
	if (clear_pgm_int() == PGM_INT_CODE_SPECIFICATION) {
		report_skip("diag258 not supported");
	} else {
		test_priv();
		/* Other tests rely on invalid diagcodes doing nothing */
		test_refbk_invalid_diagcode();
		test_refbk_real();
		test_refbk_prefixing();
		test_refbk_crossing();
	}

	report_prefix_pop();
	return report_summary();
}
