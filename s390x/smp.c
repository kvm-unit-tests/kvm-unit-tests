/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests sigp emulation
 *
 * Copyright 2019 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
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

static void wait_for_flag(void)
{
	while (!testflag)
		mb();
}

static void set_flag(int val)
{
	mb();
	testflag = val;
	mb();
}

static void test_func(void)
{
	set_flag(1);
}

static void test_start(void)
{
	struct psw psw;
	psw.mask = extract_psw_mask();
	psw.addr = (unsigned long)test_func;

	set_flag(0);
	smp_cpu_start(1, psw);
	wait_for_flag();
	report(1, "start");
}

/*
 * Does only test restart when the target is running.
 * The other tests do restarts when stopped multiple times already.
 */
static void test_restart(void)
{
	struct cpu *cpu = smp_cpu_from_addr(1);
	struct lowcore *lc = cpu->lowcore;

	lc->restart_new_psw.mask = extract_psw_mask();
	lc->restart_new_psw.addr = (unsigned long)test_func;

	/* Make sure cpu is running */
	smp_cpu_stop(0);
	set_flag(0);
	smp_cpu_restart(1);
	wait_for_flag();

	/*
	 * Wait until cpu 1 has set the flag because it executed the
	 * restart function.
	 */
	set_flag(0);
	smp_cpu_restart(1);
	wait_for_flag();
	report(1, "restart while running");
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
	report(1, "stop");
}

static void test_stop_store_status(void)
{
	struct cpu *cpu = smp_cpu_from_addr(1);
	struct lowcore *lc = (void *)0x0;

	report_prefix_push("stop store status");
	report_prefix_push("running");
	smp_cpu_restart(1);
	lc->prefix_sa = 0;
	lc->grs_sa[15] = 0;
	smp_cpu_stop_store_status(1);
	mb();
	report(lc->prefix_sa == (uint32_t)(uintptr_t)cpu->lowcore, "prefix");
	report(lc->grs_sa[15], "stack");
	report(smp_cpu_stopped(1), "cpu stopped");
	report_prefix_pop();

	report_prefix_push("stopped");
	lc->prefix_sa = 0;
	lc->grs_sa[15] = 0;
	smp_cpu_stop_store_status(1);
	mb();
	report(lc->prefix_sa == (uint32_t)(uintptr_t)cpu->lowcore, "prefix");
	report(lc->grs_sa[15], "stack");
	report_prefix_pop();

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
	report(r == SIGP_STATUS_INCORRECT_STATE, "incorrect state");
	report(!memcmp(status, (void *)status + PAGE_SIZE, PAGE_SIZE),
	       "status not written");
	report_prefix_pop();

	memset(status, 0, PAGE_SIZE);
	report_prefix_push("stopped");
	smp_cpu_stop(1);
	sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, NULL);
	while (!status->prefix) { mb(); }
	report(1, "status written");
	free_pages(status);
	report_prefix_pop();
	smp_cpu_stop(1);

	report_prefix_pop();
}

static void ecall(void)
{
	unsigned long mask;
	struct lowcore *lc = (void *)0x0;

	expect_ext_int();
	ctl_set_bit(0, CTL0_EXTERNAL_CALL);
	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
	set_flag(1);
	while (lc->ext_int_code != 0x1202) { mb(); }
	report(1, "received");
	set_flag(1);
}

static void test_ecall(void)
{
	struct psw psw;
	psw.mask = extract_psw_mask();
	psw.addr = (unsigned long)ecall;

	report_prefix_push("ecall");
	set_flag(0);

	smp_cpu_start(1, psw);
	wait_for_flag();
	set_flag(0);
	sigp(1, SIGP_EXTERNAL_CALL, 0, NULL);
	wait_for_flag();
	smp_cpu_stop(1);
	report_prefix_pop();
}

static void emcall(void)
{
	unsigned long mask;
	struct lowcore *lc = (void *)0x0;

	expect_ext_int();
	ctl_set_bit(0, CTL0_EMERGENCY_SIGNAL);
	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
	set_flag(1);
	while (lc->ext_int_code != 0x1201) { mb(); }
	report(1, "received");
	set_flag(1);
}

static void test_emcall(void)
{
	struct psw psw;
	psw.mask = extract_psw_mask();
	psw.addr = (unsigned long)emcall;

	report_prefix_push("emcall");
	set_flag(0);

	smp_cpu_start(1, psw);
	wait_for_flag();
	set_flag(0);
	sigp(1, SIGP_EMERGENCY_SIGNAL, 0, NULL);
	wait_for_flag();
	smp_cpu_stop(1);
	report_prefix_pop();
}

static void test_sense_running(void)
{
	report_prefix_push("sense_running");
	/* we (CPU0) are running */
	report(smp_sense_running_status(0), "CPU0 sense claims running");
	/* stop the target CPU (CPU1) to speed up the not running case */
	smp_cpu_stop(1);
	/* Make sure to have at least one time with a not running indication */
	while(smp_sense_running_status(1));
	report(true, "CPU1 sense claims not running");
	report_prefix_pop();
}

/* Used to dirty registers of cpu #1 before it is reset */
static void test_func_initial(void)
{
	asm volatile("sfpc %0" :: "d" (0x11));
	lctlg(1, 0x42000UL);
	lctlg(7, 0x43000UL);
	lctlg(13, 0x44000UL);
	set_flag(1);
}

static void test_reset_initial(void)
{
	struct cpu_status *status = alloc_pages(0);
	struct psw psw;
	int i;

	psw.mask = extract_psw_mask();
	psw.addr = (unsigned long)test_func_initial;

	report_prefix_push("reset initial");
	set_flag(0);
	smp_cpu_start(1, psw);
	wait_for_flag();

	sigp_retry(1, SIGP_INITIAL_CPU_RESET, 0, NULL);
	sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, NULL);

	report_prefix_push("clear");
	report(!status->psw.mask && !status->psw.addr, "psw");
	report(!status->prefix, "prefix");
	report(!status->fpc, "fpc");
	report(!status->cputm, "cpu timer");
	report(!status->todpr, "todpr");
	for (i = 1; i <= 13; i++) {
		report(status->crs[i] == 0, "cr%d == 0", i);
	}
	report(status->crs[15] == 0, "cr15 == 0");
	report_prefix_pop();

	report_prefix_push("initialized");
	report(status->crs[0] == 0xE0UL, "cr0 == 0xE0");
	report(status->crs[14] == 0xC2000000UL, "cr14 == 0xC2000000");
	report_prefix_pop();

	report(smp_cpu_stopped(1), "cpu stopped");
	free_pages(status);
	report_prefix_pop();
}

static void test_local_ints(void)
{
	unsigned long mask;

	/* Open masks for ecall and emcall */
	ctl_set_bit(0, CTL0_EXTERNAL_CALL);
	ctl_set_bit(0, CTL0_EMERGENCY_SIGNAL);
	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
	set_flag(1);
}

static void test_reset(void)
{
	struct psw psw;

	psw.mask = extract_psw_mask();
	psw.addr = (unsigned long)test_func;

	report_prefix_push("cpu reset");
	sigp(1, SIGP_EMERGENCY_SIGNAL, 0, NULL);
	sigp(1, SIGP_EXTERNAL_CALL, 0, NULL);
	smp_cpu_start(1, psw);

	sigp_retry(1, SIGP_CPU_RESET, 0, NULL);
	report(smp_cpu_stopped(1), "cpu stopped");

	set_flag(0);
	psw.addr = (unsigned long)test_local_ints;
	smp_cpu_start(1, psw);
	wait_for_flag();
	report(true, "local interrupts cleared");
	report_prefix_pop();
}

int main(void)
{
	struct psw psw;
	report_prefix_push("smp");

	if (smp_query_num_cpus() == 1) {
		report_skip("need at least 2 cpus for this test");
		goto done;
	}

	/* Setting up the cpu to give it a stack and lowcore */
	psw.mask = extract_psw_mask();
	psw.addr = (unsigned long)test_func;
	smp_cpu_setup(1, psw);
	smp_cpu_stop(1);

	test_start();
	test_restart();
	test_stop();
	test_stop_store_status();
	test_store_status();
	test_ecall();
	test_emcall();
	test_sense_running();
	test_reset();
	test_reset_initial();
	smp_cpu_destroy(1);

done:
	report_prefix_pop();
	return report_summary();
}
