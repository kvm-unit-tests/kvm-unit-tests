/*
 * Tests sigp emulation
 *
 * Copyright 2019 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm-generic/barrier.h>
#include <asm/sigp.h>

#include <smp.h>
#include <alloc_page.h>

static int testflag = 0;

static void cpu_loop(void)
{
	for (;;) {}
}

static void test_func(void)
{
	testflag = 1;
	mb();
	cpu_loop();
}

static void test_start(void)
{
	struct psw psw;
	psw.mask =  extract_psw_mask();
	psw.addr = (unsigned long)test_func;

	smp_cpu_setup(1, psw);
	while (!testflag) {
		mb();
	}
	report("start", 1);
}

static void test_stop(void)
{
	smp_cpu_stop(1);
	/*
	 * The smp library waits for the CPU to shut down, but let's
	 * also do it here, so we don't rely on the library
	 * implementation
	 */
	while (!smp_cpu_stopped(1)) {}
	report("stop", 1);
}

static void test_stop_store_status(void)
{
	struct cpu *cpu = smp_cpu_from_addr(1);
	struct lowcore *lc = (void *)0x0;

	report_prefix_push("stop store status");
	lc->prefix_sa = 0;
	lc->grs_sa[15] = 0;
	smp_cpu_stop_store_status(1);
	mb();
	report("prefix", lc->prefix_sa == (uint32_t)(uintptr_t)cpu->lowcore);
	report("stack", lc->grs_sa[15]);
	report_prefix_pop();
}

static void test_store_status(void)
{
	struct cpu_status *status = alloc_pages(1);
	uint32_t r;

	report_prefix_push("store status at address");
	memset(status, 0, PAGE_SIZE * 2);

	report_prefix_push("running");
	smp_cpu_restart(1);
	sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, &r);
	report("incorrect state", r == SIGP_STATUS_INCORRECT_STATE);
	report("status not written", !memcmp(status, (void*)status + PAGE_SIZE, PAGE_SIZE));
	report_prefix_pop();

	memset(status, 0, PAGE_SIZE);
	report_prefix_push("stopped");
	smp_cpu_stop(1);
	sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, NULL);
	while (!status->prefix) { mb(); }
	report("status written", 1);
	free_pages(status, PAGE_SIZE * 2);
	report_prefix_pop();

	report_prefix_pop();
}

static void ecall(void)
{
	unsigned long mask;
	struct lowcore *lc = (void *)0x0;

	expect_ext_int();
	ctl_set_bit(0, 13);
	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
	testflag = 1;
	while (lc->ext_int_code != 0x1202) { mb(); }
	report("ecall", 1);
	testflag= 1;
}

static void test_ecall(void)
{
	struct psw psw;
	psw.mask =  extract_psw_mask();
	psw.addr = (unsigned long)ecall;

	report_prefix_push("ecall");
	testflag= 0;
	smp_cpu_destroy(1);

	smp_cpu_setup(1, psw);
	while (!testflag) { mb(); }
	testflag= 0;
	sigp(1, SIGP_EXTERNAL_CALL, 0, NULL);
	while(!testflag) {mb();}
	smp_cpu_stop(1);
	report_prefix_pop();
}

static void emcall(void)
{
	unsigned long mask;
	struct lowcore *lc = (void *)0x0;

	expect_ext_int();
	ctl_set_bit(0, 14);
	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
	testflag= 1;
	while (lc->ext_int_code != 0x1201) { mb(); }
	report("ecall", 1);
	testflag = 1;
}

static void test_emcall(void)
{
	struct psw psw;
	psw.mask =  extract_psw_mask();
	psw.addr = (unsigned long)emcall;

	report_prefix_push("emcall");
	testflag= 0;
	smp_cpu_destroy(1);

	smp_cpu_setup(1, psw);
	while (!testflag) { mb(); }
	testflag= 0;
	sigp(1, SIGP_EMERGENCY_SIGNAL, 0, NULL);
	while(!testflag) { mb(); }
	smp_cpu_stop(1);
	report_prefix_pop();
}

static void test_reset_initial(void)
{
	struct cpu_status *status = alloc_pages(0);
	struct psw psw;

	psw.mask =  extract_psw_mask();
	psw.addr = (unsigned long)test_func;

	report_prefix_push("reset initial");
	smp_cpu_setup(1, psw);

	sigp_retry(1, SIGP_INITIAL_CPU_RESET, 0, NULL);
	sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, NULL);

	report_prefix_push("clear");
	report("psw", !status->psw.mask && !status->psw.addr);
	report("prefix", !status->prefix);
	report("fpc", !status->fpc);
	report("cpu timer", !status->cputm);
	report("todpr", !status->todpr);
	report_prefix_pop();

	report_prefix_push("initialized");
	report("cr0 == 0xE0", status->crs[0] == 0xE0UL);
	report("cr14 == 0xC2000000", status->crs[14] == 0xC2000000UL);
	report_prefix_pop();

	report("cpu stopped", smp_cpu_stopped(1));
	free_pages(status, PAGE_SIZE);
	report_prefix_pop();
}

static void test_reset(void)
{
	struct psw psw;

	psw.mask =  extract_psw_mask();
	psw.addr = (unsigned long)test_func;

	report_prefix_push("cpu reset");
	smp_cpu_setup(1, psw);

	sigp_retry(1, SIGP_CPU_RESET, 0, NULL);
	report("cpu stopped", smp_cpu_stopped(1));
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("smp");

	if (smp_query_num_cpus() == 1) {
		report_skip("need at least 2 cpus for this test");
		goto done;
	}

	test_start();
	test_stop();
	test_stop_store_status();
	test_store_status();
	test_ecall();
	test_emcall();
	test_reset();
	test_reset_initial();

done:
	report_prefix_pop();
	return report_summary();
}
