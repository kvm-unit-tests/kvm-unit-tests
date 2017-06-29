/*
 * Interception tests - for s390x CPU instruction that cause a VM exit
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>

static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));

static unsigned long nr_iterations;
static unsigned long time_to_run;

/* Test the STORE PREFIX instruction */
static void test_stpx(void)
{
	uint32_t old_prefix = -1U, tst_prefix = -1U;
	uint32_t new_prefix = (uint32_t)(intptr_t)pagebuf;

	/* Can we successfully change the prefix? */
	asm volatile (
		" stpx	%0\n"
		" spx	%2\n"
		" stpx	%1\n"
		" spx	%0\n"
		: "+Q"(old_prefix), "+Q"(tst_prefix)
		: "Q"(new_prefix));
	report("store prefix", old_prefix == 0 && tst_prefix == new_prefix);

	expect_pgm_int();
	low_prot_enable();
	asm volatile(" stpx 0(%0) " : : "r"(8));
	low_prot_disable();
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);

	expect_pgm_int();
	asm volatile(" stpx 0(%0) " : : "r"(1));
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	expect_pgm_int();
	asm volatile(" stpx 0(%0) " : : "r"(-8));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

/* Test the SET PREFIX instruction */
static void test_spx(void)
{
	uint32_t new_prefix = (uint32_t)(intptr_t)pagebuf;
	uint32_t old_prefix;

	memset(pagebuf, 0, PAGE_SIZE * 2);

	/*
	 * Temporarily change the prefix page to our buffer, and store
	 * some facility bits there ... at least some of them should be
	 * set in our buffer afterwards.
	 */
	asm volatile (
		" stpx	%0\n"
		" spx	%1\n"
		" stfl	0\n"
		" spx	%0\n"
		: "+Q"(old_prefix)
		: "Q"(new_prefix)
		: "memory");
	report("stfl to new prefix", pagebuf[GEN_LC_STFL] != 0);

	expect_pgm_int();
	asm volatile(" spx 0(%0) " : : "r"(1));
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	expect_pgm_int();
	asm volatile(" spx 0(%0) " : : "r"(-8));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

/* Test the STORE CPU ADDRESS instruction */
static void test_stap(void)
{
	uint16_t cpuid = 0xffff;

	asm volatile ("stap %0\n" : "+Q"(cpuid));
	report("get cpu address", cpuid != 0xffff);

	expect_pgm_int();
	low_prot_enable();
	asm volatile ("stap 0(%0)\n" : : "r"(8));
	low_prot_disable();
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);

	expect_pgm_int();
	asm volatile ("stap 0(%0)\n" : : "r"(1));
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	expect_pgm_int();
	asm volatile ("stap 0(%0)\n" : : "r"(-8));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

/* Test the STORE CPU ID instruction */
static void test_stidp(void)
{
	struct cpuid id = {};

	asm volatile ("stidp %0\n" : "+Q"(id));
	report("type set", id.type);
	report("version valid", !id.version || id.version == 0xff);
	report("reserved bits not set", !id.reserved);

	expect_pgm_int();
	low_prot_enable();
	asm volatile ("stidp 0(%0)\n" : : "r"(8));
	low_prot_disable();
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);

	expect_pgm_int();
	asm volatile ("stidp 0(%0)\n" : : "r"(1));
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

	expect_pgm_int();
	asm volatile ("stidp 0(%0)\n" : : "r"(-8));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

/* Test the TEST BLOCK instruction */
static void test_testblock(void)
{
	int cc;

	memset(pagebuf, 0xaa, PAGE_SIZE);

	asm volatile (
		" lghi	%%r0,0\n"
		" tb	%1\n"
		" ipm	%0\n"
		" srl	%0,28\n"
		: "=d" (cc)
		: "a"(pagebuf + 0x123)
		: "memory", "0", "cc");
	report("page cleared",
	       cc == 0 && pagebuf[0] == 0 &&  pagebuf[PAGE_SIZE - 1] == 0);

	expect_pgm_int();
	low_prot_enable();
	asm volatile (" tb %0 " : : "r"(4096));
	low_prot_disable();
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);

	expect_pgm_int();
	asm volatile (" tb %0 " : : "r"(-4096));
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
}

static uint64_t get_clock_ms(void)
{
	uint64_t clk;

	asm volatile(" stck %0 " : : "Q"(clk) : "memory");

	/* Bit 51 is incrememented each microsecond */
	return (clk >> (63 - 51)) / 1000;
}

struct {
	const char *name;
	void (*func)(void);
	bool run_it;
} tests[] = {
	{ "stpx", test_stpx, false },
	{ "spx", test_spx, false },
	{ "stap", test_stap, false },
	{ "stidp", test_stidp, false },
	{ "testblock", test_testblock, false },
	{ NULL, NULL, false }
};

static void parse_intercept_test_args(int argc, char **argv)
{
	int i, ti;
	bool run_all = true;

	for (i = 1; i < argc; i++) {
		if (!strcmp("-i", argv[i])) {
			i++;
			if (i >= argc)
				report_abort("-i needs a parameter");
			nr_iterations = atol(argv[i]);
		} else if (!strcmp("-t", argv[i])) {
			i++;
			if (i >= argc)
				report_abort("-t needs a parameter");
			time_to_run = atol(argv[i]);
		} else for (ti = 0; tests[ti].name != NULL; ti++) {
			if (!strcmp(tests[ti].name, argv[i])) {
				run_all = false;
				tests[ti].run_it = true;
				break;
			} else if (tests[ti + 1].name == NULL) {
				report_abort("Unsupported parameter '%s'",
					     argv[i]);
			}
		}
	}

	if (run_all) {
		for (ti = 0; tests[ti].name != NULL; ti++)
			tests[ti].run_it = true;
	}
}

int main(int argc, char **argv)
{
	uint64_t startclk;
	int ti;

	parse_intercept_test_args(argc, argv);

	if (nr_iterations == 0 && time_to_run == 0)
		nr_iterations = 1;

	report_prefix_push("intercept");

	startclk = get_clock_ms();
	for (;;) {
		for (ti = 0; tests[ti].name != NULL; ti++) {
			report_prefix_push(tests[ti].name);
			if (tests[ti].run_it)
				tests[ti].func();
			report_prefix_pop();
		}
		if (nr_iterations) {
			nr_iterations -= 1;
			if (nr_iterations == 0)
				break;
		}
		if (time_to_run) {
			if (get_clock_ms() - startclk > time_to_run)
				break;
		}
	}

	report_prefix_pop();

	return report_summary();
}
