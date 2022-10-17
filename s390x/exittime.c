/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Measure run time of various instructions. Can be used to find runtime
 * regressions of instructions which cause exits.
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <smp.h>
#include <sclp.h>
#include <hardware.h>
#include <asm/time.h>
#include <asm/sigp.h>
#include <asm/interrupt.h>
#include <asm/page.h>

const uint64_t iters_to_normalize_to = 10000;
char pagebuf[PAGE_SIZE] __attribute__((__aligned__(PAGE_SIZE)));

static void test_sigp_sense_running(long destcpu)
{
	smp_sigp(destcpu, SIGP_SENSE_RUNNING, 0, NULL);
}

static void test_nop(long ignore)
{
	/* nops don't trap into the hypervisor, so let's test them for reference */
	asm volatile(
		"nop"
		:
		:
		: "memory"
	);
}

static void test_diag9c(long destcpu)
{
	asm volatile(
		"diag %[destcpu],0,0x9c"
		:
		: [destcpu] "d" (destcpu)
	);
}

static long setup_get_this_cpuaddr(long ignore)
{
	return stap();
}

static void test_diag44(long ignore)
{
	asm volatile(
		"diag 0,0,0x44"
	);
}

static void test_stnsm(long ignore)
{
	int out;

	asm volatile(
		"stnsm %[out],0xff"
		: [out] "=Q" (out)
	);
}

static void test_stosm(long ignore)
{
	int out;

	asm volatile(
		"stosm %[out],0"
		: [out] "=Q" (out)
	);
}

static long setup_ssm(long ignore)
{
	long system_mask = 0;

	asm volatile(
		"stosm %[system_mask],0"
		: [system_mask] "=Q" (system_mask)
	);

	return system_mask;
}

static void test_ssm(long old_system_mask)
{
	asm volatile(
		"ssm %[old_system_mask]"
		:
		: [old_system_mask] "Q" (old_system_mask)
	);
}

static long setup_lctl4(long ignore)
{
	long ctl4_orig = 0;

	asm volatile(
		"stctg 4,4,%[ctl4_orig]"
		: [ctl4_orig] "=S" (ctl4_orig)
	);

	return ctl4_orig;
}

static void test_lctl4(long ctl4_orig)
{
	asm volatile(
		"lctlg 4,4,%[ctl4_orig]"
		:
		: [ctl4_orig] "S" (ctl4_orig)
	);
}

static void test_stpx(long ignore)
{
	unsigned int prefix;

	asm volatile(
		"stpx %[prefix]"
		: [prefix] "=Q" (prefix)
	);
}

static void test_stfl(long ignore)
{
	asm volatile(
		"stfl 0"
		:
		:
		: "memory"
	);
}

static void test_epsw(long ignore)
{
	long r1, r2;

	asm volatile(
		"epsw %[r1], %[r2]"
		: [r1] "=d" (r1), [r2] "=d" (r2)
	);
}

static void test_illegal(long ignore)
{
	expect_pgm_int();
	asm volatile(
		".word 0"
	);
	clear_pgm_int();
}

static long setup_servc(long arg)
{
	memset(pagebuf, 0, PAGE_SIZE);
	return arg;
}

static void test_servc(long ignore)
{
	SCCB *sccb = (SCCB *) pagebuf;

	sccb->h.length = 8;
	servc(0, (unsigned long) sccb);
}

static void test_stsi(long fc)
{
	stsi(pagebuf, fc, 2, 2);
}

struct test {
	const char *name;
	bool supports_tcg;
	/*
	 * When non-null, will be called once before running the test loop.
	 * Its return value will be given as argument to testfunc.
	 */
	long (*setupfunc)(long arg);
	void (*testfunc)(long arg);
	long arg;
	long iters;
} const exittime_tests[] = {
	{"nop",                   true,  NULL,                   test_nop,                0, 200000 },
	{"sigp sense running(0)", true,  NULL,                   test_sigp_sense_running, 0, 20000 },
	{"sigp sense running(1)", true,  NULL,                   test_sigp_sense_running, 1, 20000 },
	{"diag9c(self)",          false, setup_get_this_cpuaddr, test_diag9c,             0, 2000 },
	{"diag9c(0)",             false, NULL,                   test_diag9c,             0, 2000 },
	{"diag9c(1)",             false, NULL,                   test_diag9c,             1, 2000 },
	{"diag44",                true,  NULL,                   test_diag44,             0, 2000 },
	{"stnsm",                 true,  NULL,                   test_stnsm,              0, 200000 },
	{"stosm",                 true,  NULL,                   test_stosm,              0, 200000 },
	{"ssm",                   true,  setup_ssm,              test_ssm,                0, 200000 },
	{"lctl4",                 true,  setup_lctl4,            test_lctl4,              0, 20000 },
	{"stpx",                  true,  NULL,                   test_stpx,               0, 2000 },
	{"stfl",                  true,  NULL,                   test_stfl,               0, 2000 },
	{"epsw",                  true,  NULL,                   test_epsw,               0, 20000 },
	{"illegal",               true,  NULL,                   test_illegal,            0, 2000 },
	{"servc",                 true,  setup_servc,            test_servc,              0, 2000 },
	{"stsi122",               true,  NULL,                   test_stsi,               1, 200 },
	{"stsi222",               true,  NULL,                   test_stsi,               2, 200 },
	{"stsi322",               true,  NULL,                   test_stsi,               3, 200 },
};

struct test_result {
	uint64_t total;
	uint64_t best;
	uint64_t average;
	uint64_t worst;
};

static uint64_t tod_to_us(uint64_t tod)
{
	return tod >> STCK_SHIFT_US;
}

static uint64_t tod_to_ns(uint64_t tod)
{
	return tod_to_us(tod * 1000);
}

static uint64_t normalize_iters(uint64_t value_to_normalize, uint64_t iters)
{
	return value_to_normalize * iters_to_normalize_to / iters;
}

static void report_iteration_result(struct test const* test, struct test_result const* test_result)
{
	uint64_t total = tod_to_ns(normalize_iters(test_result->total, test->iters)),
		 best = tod_to_ns(normalize_iters(test_result->best, test->iters)),
		 average = tod_to_ns(normalize_iters(test_result->average, test->iters)),
		 worst = tod_to_ns(normalize_iters(test_result->worst, test->iters));

	report_pass(
		"total/best/avg/worst %lu.%03lu/%lu.%03lu/%lu.%03lu/%lu.%03lu us",
		total / 1000, total % 1000,
		best / 1000, best % 1000,
		average / 1000, average % 1000,
		worst / 1000, worst % 1000
	);
}

int main(void)
{
	int i, j, k, testfunc_arg;
	const int outer_iters = 100;
	struct test const *current_test;
	struct test_result result;
	uint64_t start, end, elapsed;

	report_prefix_push("exittime");
	report_info("reporting total/best/avg/worst normalized to %lu iterations", iters_to_normalize_to);

	for (i = 0; i < ARRAY_SIZE(exittime_tests); i++) {
		current_test = &exittime_tests[i];
		result.total = 0;
		result.worst = 0;
		result.best = -1;
		report_prefix_pushf("%s", current_test->name);

		if (host_is_tcg() && !current_test->supports_tcg) {
			report_skip("not supported under TCG");
			report_prefix_pop();
			continue;
		}

		testfunc_arg = current_test->arg;
		if (current_test->setupfunc)
			testfunc_arg = current_test->setupfunc(testfunc_arg);

		for (j = 0; j < outer_iters; j++) {
			stckf(&start);
			for (k = 0; k < current_test->iters; k++)
				current_test->testfunc(testfunc_arg);
			stckf(&end);
			elapsed = end - start;
			result.best = MIN(result.best, elapsed);
			result.worst = MAX(result.worst, elapsed);
			result.total += elapsed;
		}
		result.average = result.total / outer_iters;
		report_iteration_result(current_test, &result);
		report_prefix_pop();
	}

	report_prefix_pop();
	return report_summary();
}
