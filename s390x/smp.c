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
#include <uv.h>
#include <alloc_page.h>

static int testflag = 0;
#define INVALID_CPU_ADDRESS -4711
#define INVALID_ORDER_CODE 0xFF
struct sigp_invalid_cases {
	int order;
	char message[100];
};
static const struct sigp_invalid_cases cases_invalid_cpu_addr[] = {
	{ SIGP_STOP,                  "stop with invalid CPU address" },
	{ SIGP_START,                 "start with invalid CPU address" },
	{ SIGP_CPU_RESET,             "reset with invalid CPU address" },
	{ SIGP_COND_EMERGENCY_SIGNAL, "conditional emcall with invalid CPU address" },
	{ SIGP_EMERGENCY_SIGNAL,      "emcall with invalid CPU address" },
	{ SIGP_EXTERNAL_CALL,         "ecall with invalid CPU address" },
	{ INVALID_ORDER_CODE,         "invalid order code and CPU address" },
	{ SIGP_SENSE,                 "sense with invalid CPU address" },
	{ SIGP_STOP_AND_STORE_STATUS, "stop and store status with invalid CPU address" },
};
static const struct sigp_invalid_cases cases_valid_cpu_addr[] = {
	{ INVALID_ORDER_CODE,         "invalid order code" },
};

static uint32_t cpu1_prefix;

struct sigp_call_cases {
	char name[20];
	int call;
	uint16_t ext_int_expected_type;
	unsigned int cr0_bit;
	bool supports_pv;
};
static const struct sigp_call_cases cases_sigp_call[] = {
	{ "emcall",      SIGP_EMERGENCY_SIGNAL,      0x1201, CTL0_EMERGENCY_SIGNAL, true },
	{ "cond emcall", SIGP_COND_EMERGENCY_SIGNAL, 0x1201, CTL0_EMERGENCY_SIGNAL, false },
	{ "ecall",       SIGP_EXTERNAL_CALL,         0x1202, CTL0_EXTERNAL_CALL,    true },
};
static const struct sigp_call_cases *current_sigp_call_case;

static void test_invalid(void)
{
	const struct sigp_invalid_cases *c;
	uint32_t status;
	int cc;
	int i;

	report_prefix_push("invalid parameters");

	for (i = 0; i < ARRAY_SIZE(cases_invalid_cpu_addr); i++) {
		c = &cases_invalid_cpu_addr[i];
		cc = sigp(INVALID_CPU_ADDRESS, c->order, 0, &status);
		report(cc == 3, "%s", c->message);
	}

	for (i = 0; i < ARRAY_SIZE(cases_valid_cpu_addr); i++) {
		c = &cases_valid_cpu_addr[i];
		cc = smp_sigp(1, c->order, 0, &status);
		report(cc == 1, "%s", c->message);
	}

	report_prefix_pop();
}

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
	set_flag(0);
	smp_cpu_start(1, PSW_WITH_CUR_MASK(test_func));
	wait_for_flag();
	report_pass("start");
}

static void test_restart(void)
{
	struct cpu *cpu = smp_cpu_from_idx(1);
	struct lowcore *lc = cpu->lowcore;
	int rc;

	report_prefix_push("restart");
	report_prefix_push("stopped");

	lc->restart_new_psw = PSW_WITH_CUR_MASK(test_func);

	/* Make sure cpu is stopped */
	smp_cpu_stop(1);
	set_flag(0);
	rc = smp_cpu_restart_nowait(1);
	report(!rc, "return code");
	report(!smp_cpu_stopped(1), "cpu started");
	wait_for_flag();
	report_pass("test flag");

	report_prefix_pop();
	report_prefix_push("running");

	/*
	 * Wait until cpu 1 has set the flag because it executed the
	 * restart function.
	 */
	set_flag(0);
	rc = smp_cpu_restart_nowait(1);
	report(!rc, "return code");
	report(!smp_cpu_stopped(1), "cpu started");
	wait_for_flag();
	report_pass("test flag");

	report_prefix_pop();
	report_prefix_pop();
}

static void test_stop(void)
{
	int rc;

	report_prefix_push("stop");

	rc = smp_cpu_stop_nowait(1);
	report(!rc, "return code");
	report(smp_cpu_stopped(1), "cpu stopped");

	report_prefix_push("stop stopped CPU");
	rc = smp_cpu_stop_nowait(1);
	report(!rc, "return code");
	report(smp_cpu_stopped(1), "cpu stopped");
	report_prefix_pop();

	report_prefix_pop();
}

static void test_stop_store_status(void)
{
	struct cpu *cpu = smp_cpu_from_idx(1);

	report_prefix_push("stop store status");
	report_prefix_push("running");
	smp_cpu_restart(1);
	lowcore.prefix_sa = 0;
	lowcore.grs_sa[15] = 0;
	smp_cpu_stop_store_status(1);
	mb();
	report(smp_cpu_stopped(1), "cpu stopped");
	report(lowcore.prefix_sa == (uint32_t)(uintptr_t)cpu->lowcore, "prefix");
	report(lowcore.grs_sa[15], "stack");
	report_prefix_pop();

	report_prefix_push("stopped");
	lowcore.prefix_sa = 0;
	lowcore.grs_sa[15] = 0;
	smp_cpu_stop_store_status(1);
	mb();
	report(smp_cpu_stopped(1), "cpu stopped");
	report(lowcore.prefix_sa == (uint32_t)(uintptr_t)cpu->lowcore, "prefix");
	report(lowcore.grs_sa[15], "stack");
	report_prefix_pop();

	report_prefix_pop();
}

static void test_store_status(void)
{
	struct cpu_status *status = alloc_pages_flags(1, AREA_DMA31);
	uint32_t r;
	int cc;

	report_prefix_push("store status at address");
	memset(status, 0, PAGE_SIZE * 2);

	report_prefix_push("invalid CPU address");
	cc = sigp(INVALID_CPU_ADDRESS, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, &r);
	report(cc == 3, "returned with CC = 3");
	report_prefix_pop();

	report_prefix_push("running");
	smp_cpu_restart(1);
	smp_sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, &r);
	report(r == SIGP_STATUS_INCORRECT_STATE, "incorrect state");
	report(!memcmp(status, (void *)status + PAGE_SIZE, PAGE_SIZE),
	       "status not written");
	report_prefix_pop();

	memset(status, 0, PAGE_SIZE);
	report_prefix_push("stopped");
	smp_cpu_stop(1);
	smp_sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, NULL);
	while (!status->prefix) { mb(); }
	report_pass("status written");
	free_pages(status);
	report_prefix_pop();
	smp_cpu_stop(1);

	report_prefix_pop();
}

static void loop(void)
{
	while (1)
		;
}

static void stpx_and_set_flag(void)
{
	asm volatile (
		"	stpx %[prefix]\n"
		: [prefix] "=Q" (cpu1_prefix)
		:
		:
	);

	set_flag(1);
}

static void test_set_prefix(void)
{
	struct lowcore *new_lc = alloc_pages_flags(1, AREA_DMA31);
	struct cpu *cpu1 = smp_cpu_from_idx(1);
	uint32_t status = 0;
	int cc;

	report_prefix_push("set prefix");

	assert(new_lc);

	memcpy(new_lc, cpu1->lowcore, sizeof(struct lowcore));
	new_lc->restart_new_psw.addr = (unsigned long)loop;

	report_prefix_push("running");
	set_flag(0);
	smp_cpu_start(1, PSW_WITH_CUR_MASK(stpx_and_set_flag));
	wait_for_flag();
	cpu1_prefix = 0xFFFFFFFF;

	cc = smp_sigp(1, SIGP_SET_PREFIX, (unsigned long)new_lc, &status);
	report(cc == 1, "CC = 1");
	report(status == SIGP_STATUS_INCORRECT_STATE, "status = INCORRECT_STATE");

	/*
	 * If the prefix of the other CPU was changed it will enter an endless
	 * loop. Otherwise, it should eventually set the flag.
	 */
	smp_cpu_stop(1);
	set_flag(0);
	smp_cpu_restart(1);
	wait_for_flag();
	report(cpu1_prefix == (uint64_t)cpu1->lowcore, "prefix unchanged");

	report_prefix_pop();

	report_prefix_push("invalid CPU address");

	cc = sigp(INVALID_CPU_ADDRESS, SIGP_SET_PREFIX, (unsigned long)new_lc, &status);
	report(cc == 3, "CC = 3");

	report_prefix_pop();

	free_pages(new_lc);

	report_prefix_pop();

}

static void call_received(void)
{
	expect_ext_int();
	ctl_set_bit(0, current_sigp_call_case->cr0_bit);
	/* make sure conditional emergency is accepted by disabling IO interrupts */
	psw_mask_clear_and_set_bits(PSW_MASK_IO, PSW_MASK_EXT);

	/* Indicate that we're ready to receive the call */
	set_flag(1);

	while (lowcore.ext_int_code != current_sigp_call_case->ext_int_expected_type)
		mb();
	report_pass("received");

	ctl_clear_bit(0, current_sigp_call_case->cr0_bit);

	/* Indicate that we're done */
	set_flag(1);
}

static void test_calls(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cases_sigp_call); i++) {
		current_sigp_call_case = &cases_sigp_call[i];

		report_prefix_push(current_sigp_call_case->name);
		if (!current_sigp_call_case->supports_pv && uv_os_is_guest()) {
			report_skip("Not supported under PV");
			report_prefix_pop();
			continue;
		}

		set_flag(0);
		smp_cpu_start(1, PSW_WITH_CUR_MASK(call_received));

		/* Wait until the receiver has finished setup */
		wait_for_flag();
		set_flag(0);

		smp_sigp(1, current_sigp_call_case->call, 0, NULL);

		/* Wait until the receiver has handled the call */
		wait_for_flag();
		smp_cpu_stop(1);
		report_prefix_pop();
	}
}

static void call_in_wait_ext_int_fixup(struct stack_frame_int *stack)
{
	/* Clear wait bit so we don't immediately wait again after the fixup */
	lowcore.ext_old_psw.mask &= ~PSW_MASK_WAIT;
}

static void call_in_wait_setup(void)
{
	expect_ext_int();
	ctl_set_bit(0, current_sigp_call_case->cr0_bit);
	register_ext_cleanup_func(call_in_wait_ext_int_fixup);

	set_flag(1);
}

static void call_in_wait_received(void)
{
	report(lowcore.ext_int_code == current_sigp_call_case->ext_int_expected_type, "received");

	set_flag(1);
}

static void call_in_wait_cleanup(void)
{
	ctl_clear_bit(0, current_sigp_call_case->cr0_bit);
	register_ext_cleanup_func(NULL);

	set_flag(1);
}

static void test_calls_in_wait(void)
{
	int i;

	report_prefix_push("psw wait");
	for (i = 0; i < ARRAY_SIZE(cases_sigp_call); i++) {
		current_sigp_call_case = &cases_sigp_call[i];

		report_prefix_push(current_sigp_call_case->name);
		if (!current_sigp_call_case->supports_pv && uv_os_is_guest()) {
			report_skip("Not supported under PV");
			report_prefix_pop();
			continue;
		}

		/* Let the secondary CPU setup the external mask and the external interrupt cleanup function */
		set_flag(0);
		smp_cpu_start(1, PSW_WITH_CUR_MASK(call_in_wait_setup));

		/* Wait until the receiver has finished setup */
		wait_for_flag();
		set_flag(0);

		/*
		 * To avoid races, we need to know that the secondary CPU has entered wait,
		 * but the architecture provides no way to check whether the secondary CPU
		 * is in wait.
		 *
		 * But since a waiting CPU is considered operating, simply stop the CPU, set
		 * up the restart new PSW mask in wait, send the restart interrupt and then
		 * wait until the CPU becomes operating (done by smp_cpu_start).
		 */
		smp_cpu_stop(1);
		smp_cpu_start(1, PSW(extract_psw_mask() | PSW_MASK_EXT | PSW_MASK_WAIT, call_in_wait_received));

		smp_sigp(1, current_sigp_call_case->call, 0, NULL);

		/* Wait until the receiver has handled the call */
		wait_for_flag();
		smp_cpu_stop(1);
		set_flag(0);

		/*
		 * Now clean up the mess we have left behind. If the cleanup
		 * were part of call_in_wait_received we would not get a chance
		 * to catch an interrupt that is presented twice since we would
		 * disable the external call on the first interrupt.
		 */
		smp_cpu_start(1, PSW_WITH_CUR_MASK(call_in_wait_cleanup));

		/* Wait until the cleanup has been completed */
		wait_for_flag();
		smp_cpu_stop(1);

		report_prefix_pop();
	}
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
	report_pass("CPU1 sense claims not running");
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
	struct cpu_status *status = alloc_pages_flags(0, AREA_DMA31);
	int i;

	report_prefix_push("reset initial");
	set_flag(0);
	smp_cpu_start(1, PSW_WITH_CUR_MASK(test_func_initial));
	wait_for_flag();

	smp_sigp(1, SIGP_INITIAL_CPU_RESET, 0, NULL);
	smp_sigp(1, SIGP_STORE_STATUS_AT_ADDRESS, (uintptr_t)status, NULL);

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
	/* Open masks for ecall and emcall */
	ctl_set_bit(0, CTL0_EXTERNAL_CALL);
	ctl_set_bit(0, CTL0_EMERGENCY_SIGNAL);
	psw_mask_set_bits(PSW_MASK_EXT);
	set_flag(1);
}

static void test_reset(void)
{
	report_prefix_push("cpu reset");
	smp_sigp(1, SIGP_EMERGENCY_SIGNAL, 0, NULL);
	smp_sigp(1, SIGP_EXTERNAL_CALL, 0, NULL);
	smp_cpu_start(1, PSW_WITH_CUR_MASK(test_func));

	smp_sigp(1, SIGP_CPU_RESET, 0, NULL);
	report(smp_cpu_stopped(1), "cpu stopped");

	set_flag(0);
	smp_cpu_start(1, PSW_WITH_CUR_MASK(test_local_ints));
	wait_for_flag();
	report_pass("local interrupts cleared");
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("smp");

	if (smp_query_num_cpus() == 1) {
		report_skip("need at least 2 cpus for this test");
		goto done;
	}

	/* Setting up the cpu to give it a stack and lowcore */
	smp_cpu_setup(1, PSW_WITH_CUR_MASK(test_func));
	smp_cpu_stop(1);

	test_start();
	test_invalid();
	test_restart();
	test_stop();
	test_stop_store_status();
	test_store_status();
	test_set_prefix();
	test_calls();
	test_calls_in_wait();
	test_sense_running();
	test_reset();
	test_reset_initial();
	smp_cpu_destroy(1);

done:
	report_prefix_pop();
	return report_summary();
}
