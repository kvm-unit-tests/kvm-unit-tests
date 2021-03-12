/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Move Page instruction tests
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Claudio Imbrenda <imbrenda@linux.ibm.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm-generic/barrier.h>
#include <asm/interrupt.h>
#include <asm/pgtable.h>
#include <mmu.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/mem.h>
#include <asm/sigp.h>
#include <smp.h>
#include <alloc_page.h>
#include <bitops.h>
#include <vm.h>

/* Used to build the appropriate test values for register 0 */
#define KFC(x) ((x) << 10)
#define CCO 0x100

/* How much memory to allocate for the test */
#define MEM_ORDER 12
/* How many iterations to perform in the loops */
#define ITER 8

/* Used to generate the simple pattern */
#define MAGIC 42

static uint8_t source[PAGE_SIZE]  __attribute__((aligned(PAGE_SIZE)));
static uint8_t buffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static struct lowcore * const lc;

/* Keep track of fresh memory */
static uint8_t *fresh;

static inline int mvpg(unsigned long r0, void *dest, void *src)
{
	register unsigned long reg0 asm ("0") = r0;
	int cc;

	asm volatile("	mvpg    %1,%2\n"
		     "	ipm     %0\n"
		     "	srl     %0,28"
		: "=&d" (cc) : "a" (dest), "a" (src), "d" (reg0)
		: "memory", "cc");
	return cc;
}

/*
 * Initialize a page with a simple pattern
 */
static void init_page(uint8_t *p)
{
	int i;

	for (i = 0; i < PAGE_SIZE; i++)
		p[i] = i + MAGIC;
}

/*
 * Check if the given page contains the simple pattern
 */
static int page_ok(const uint8_t *p)
{
	int i;

	for (i = 0; i < PAGE_SIZE; i++)
		if (p[i] != (uint8_t)(i + MAGIC))
			return 0;
	return 1;
}

/*
 * Check that the Operand Access Identification matches with the values of
 * the r1 and r2 fields in the instruction format. The r1 and r2 fields are
 * in the last byte of the instruction, and the Program Old PSW will point
 * to the beginning of the instruction after the one that caused the fault
 * (the fixup code in the interrupt handler takes care of that for
 * nullifying instructions). Therefore it is enough to compare the byte
 * before the one contained in the Program Old PSW with the value of the
 * Operand Access Identification.
 */
static inline bool check_oai(void)
{
	return *(uint8_t *)(lc->pgm_old_psw.addr - 1) == lc->op_acc_id;
}

static void test_exceptions(void)
{
	int i, expected;

	report_prefix_push("exceptions");

	/*
	 * Key Function Control values 4 and 5 are allowed only in supervisor
	 * state, and even then, only if the move-page-and-set-key facility
	 * is present (STFLE bit 149)
	 */
	report_prefix_push("privileged");
	if (test_facility(149)) {
		expected = PGM_INT_CODE_PRIVILEGED_OPERATION;
		for (i = 4; i < 6; i++) {
			expect_pgm_int();
			enter_pstate();
			mvpg(KFC(i), buffer, source);
			report(clear_pgm_int() == expected, "Key Function Control value %d", i);
		}
	} else {
		report_skip("Key Function Control value %d", 4);
		report_skip("Key Function Control value %d", 5);
		i = 4;
	}
	report_prefix_pop();

	/*
	 * Invalid values of the Key Function Control, or setting the
	 * reserved bits, should result in a specification exception
	 */
	report_prefix_push("specification");
	expected = PGM_INT_CODE_SPECIFICATION;
	expect_pgm_int();
	mvpg(KFC(3), buffer, source);
	report(clear_pgm_int() == expected, "Key Function Control value 3");
	for (; i < 32; i++) {
		expect_pgm_int();
		mvpg(KFC(i), buffer, source);
		report(clear_pgm_int() == expected, "Key Function Control value %d", i);
	}
	report_prefix_pop();

	/* Operands outside memory result in addressing exceptions, as usual */
	report_prefix_push("addressing");
	expected = PGM_INT_CODE_ADDRESSING;
	expect_pgm_int();
	mvpg(0, buffer, (void *)PAGE_MASK);
	report(clear_pgm_int() == expected, "Second operand outside memory");

	expect_pgm_int();
	mvpg(0, (void *)PAGE_MASK, source);
	report(clear_pgm_int() == expected, "First operand outside memory");
	report_prefix_pop();

	report_prefix_pop();
}

static void test_success(void)
{
	int cc;

	report_prefix_push("success");
	/* Test successful scenarios, both in supervisor and problem state */
	cc = mvpg(0, buffer, source);
	report(page_ok(buffer) && !cc, "Supervisor state MVPG successful");
	memset(buffer, 0xff, PAGE_SIZE);

	enter_pstate();
	cc = mvpg(0, buffer, source);
	leave_pstate();
	report(page_ok(buffer) && !cc, "Problem state MVPG successful");

	report_prefix_pop();
}

static void test_small_loop(const void *string)
{
	uint8_t *dest;
	int i, cc;

	/* Looping over cold and warm pages helps catch VSIE bugs */
	report_prefix_push(string);
	dest = fresh;
	for (i = 0; i < ITER; i++) {
		cc = mvpg(0, fresh, source);
		report(page_ok(fresh) && !cc, "cold: %p, %p", source, fresh);
		fresh += PAGE_SIZE;
	}

	for (i = 0; i < ITER; i++) {
		memset(dest, 0, PAGE_SIZE);
		cc = mvpg(0, dest, source);
		report(page_ok(dest) && !cc, "warm: %p, %p", source, dest);
		dest += PAGE_SIZE;
	}
	report_prefix_pop();
}

static void test_mmu_prot(void)
{
	int cc;

	report_prefix_push("protection");
	report_prefix_push("cco=0");

	/* MVPG should still succeed when the source is read-only */
	protect_page(source, PAGE_ENTRY_P);
	cc = mvpg(0, fresh, source);
	report(page_ok(fresh) && !cc, "source read only");
	unprotect_page(source, PAGE_ENTRY_P);
	fresh += PAGE_SIZE;

	/*
	 * When the source or destination are invalid, a page translation
	 * exception should be raised; when the destination is read-only,
	 * a protection exception should be raised.
	 */
	protect_page(fresh, PAGE_ENTRY_P);
	expect_pgm_int();
	mvpg(0, fresh, source);
	report(clear_pgm_int() == PGM_INT_CODE_PROTECTION, "destination read only");
	fresh += PAGE_SIZE;

	report_prefix_push("source invalid");
	protect_page(source, PAGE_ENTRY_I);
	lc->op_acc_id = 0;
	expect_pgm_int();
	mvpg(0, fresh, source);
	report(clear_pgm_int() == PGM_INT_CODE_PAGE_TRANSLATION, "exception");
	unprotect_page(source, PAGE_ENTRY_I);
	report(check_oai(), "operand access ident");
	report_prefix_pop();
	fresh += PAGE_SIZE;

	report_prefix_push("destination invalid");
	protect_page(fresh, PAGE_ENTRY_I);
	lc->op_acc_id = 0;
	expect_pgm_int();
	mvpg(0, fresh, source);
	report(clear_pgm_int() == PGM_INT_CODE_PAGE_TRANSLATION, "exception");
	report(check_oai(), "operand access ident");
	report_prefix_pop();
	fresh += PAGE_SIZE;

	report_prefix_pop();
	report_prefix_push("cco=1");
	/*
	 * Setting the CCO bit should suppress page translation exceptions,
	 * but not protection exceptions.
	 */
	protect_page(fresh, PAGE_ENTRY_P);
	expect_pgm_int();
	mvpg(CCO, fresh, source);
	report(clear_pgm_int() == PGM_INT_CODE_PROTECTION, "destination read only");
	fresh += PAGE_SIZE;

	/* Known issue in TCG: CCO flag is not honoured */
	if (vm_is_tcg()) {
		report_prefix_push("TCG");
		report_skip("destination invalid");
		report_skip("source invalid");
		report_skip("source and destination invalid");
		report_prefix_pop();
	} else {
		protect_page(fresh, PAGE_ENTRY_I);
		cc = mvpg(CCO, fresh, source);
		report(cc == 1, "destination invalid");
		fresh += PAGE_SIZE;

		protect_page(source, PAGE_ENTRY_I);
		cc = mvpg(CCO, fresh, source);
		report(cc == 2, "source invalid");
		fresh += PAGE_SIZE;

		protect_page(fresh, PAGE_ENTRY_I);
		cc = mvpg(CCO, fresh, source);
		report(cc == 2, "source and destination invalid");
		fresh += PAGE_SIZE;
	}

	unprotect_page(source, PAGE_ENTRY_I);
	report_prefix_pop();
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("mvpg");

	init_page(source);
	fresh = alloc_pages_flags(MEM_ORDER, FLAG_DONTZERO | FLAG_FRESH);
	assert(fresh);

	test_exceptions();
	test_success();
	test_small_loop("nommu");

	setup_vm();

	test_small_loop("mmu");
	test_mmu_prot();

	report_prefix_pop();
	return report_summary();
}
