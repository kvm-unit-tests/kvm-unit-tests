/* SPDX-License-Identifier: LGPL-2.0-only */
/*
 * SMP and IPI Tests
 *
 * Copyright 2024 Nicholas Piggin, IBM Corp.
 */
#include <libcflat.h>
#include <asm/atomic.h>
#include <asm/barrier.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/smp.h>
#include <asm/setup.h>
#include <asm/ppc_asm.h>
#include <devicetree.h>

static volatile bool start_test_running = true;
static volatile int nr_cpus_started;

static void start_fn(int cpu_id)
{
	atomic_fetch_inc(&nr_cpus_started);
	while (start_test_running)
		cpu_relax();
	atomic_fetch_dec(&nr_cpus_started);
}

static void test_start_cpus(int argc, char **argv)
{
	uint64_t tb;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	nr_cpus_started = 1;
	if (!start_all_cpus(start_fn))
		report_abort("Failed to start secondary cpus");

	tb = get_tb();
	while (nr_cpus_started < nr_cpus_present) {
		cpu_relax();
		if (get_tb() - tb > tb_hz * 5)
			report_abort("Failed to start all secondaries");
	}

	if (nr_cpus_started != nr_cpus_online)
		report_abort("Started CPUs does not match online");

	barrier();
	start_test_running = false;
	barrier();

	tb = get_tb();
	while (nr_cpus_started > 1) {
		cpu_relax();
		if (get_tb() - tb > tb_hz * 5)
			report_abort("Failed to stop all secondaries");
	}

	stop_all_cpus();

	report(true, "start cpus");
}

static volatile int nr_cpus_ipi = 0;

static void ipi_handler(struct pt_regs *regs, void *data)
{
	atomic_fetch_inc(&nr_cpus_ipi);
}

static volatile bool ipi_test_running = true;

static void ipi_fn(int cpu_id)
{
	local_ipi_enable();

	mtspr(SPR_DEC, 0x7fffffff);
	local_irq_enable();
	while (ipi_test_running)
		cpu_relax();
	local_irq_disable();

	local_ipi_disable();
}

static void test_ipi_cpus(int argc, char **argv)
{
	uint64_t tb;
	int i;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	if (nr_cpus_present < 2) {
		report_skip("Requires SMP (2 or more CPUs)");
		return;
	}

	register_ipi(ipi_handler, NULL);

	if (!start_all_cpus(ipi_fn))
		report_abort("Failed to start secondary cpus");

	for (i = 1; i < nr_cpus_online; i++)
		send_ipi(cpus[i].server_no);

	tb = get_tb();
	while (nr_cpus_ipi < nr_cpus_online - 1) {
		cpu_relax();
		if (get_tb() - tb > tb_hz * 5)
			report_abort("Secondaries failed to respond to IPIs");
	}

	send_ipi(cpus[1].server_no);

	tb = get_tb();
	while (nr_cpus_ipi < nr_cpus_online) {
		cpu_relax();
		if (get_tb() - tb > tb_hz * 5)
			report_abort("Secondaries failed to respond to IPIs");
	}

	ipi_test_running = false;

	stop_all_cpus();

	assert(nr_cpus_ipi == nr_cpus_present);

	unregister_ipi();

	report(true, "IPI cpus");
}

static uint64_t time;
static bool time_went_backward;

static void check_and_record_time(void)
{
	uint64_t tb;
	uint64_t t;
	uint64_t old;

	t = time;
again:
	barrier();
	tb = get_tb();
	asm volatile("1: ldarx %0,0,%1 ; cmpd %0,%2 ; bne 2f ; stdcx. %3,0,%1 ; bne- 1b; 2:" : "=&r"(old) : "r"(&time), "r"(t), "r"(tb) : "memory", "cr0");
	assert(tb >= t);
	if (old != t) {
		t = old;
		goto again;
	}
	if (old > tb)
		time_went_backward = true;
}

static void update_time(int64_t tb_offset)
{
	uint64_t new_tb;

	new_tb = get_tb() + tb_offset;
	mtspr(SPR_TBU40, new_tb);
	if ((get_tb() & 0xFFFFFF) < (new_tb & 0xFFFFFF)) {
		new_tb += 0x1000000;
		mtspr(SPR_TBU40, new_tb);
	}
}

static void time_sync_fn(int cpu_id)
{
	uint64_t start = get_tb();

	while (!time_went_backward && get_tb() - start < tb_hz*2) {
		check_and_record_time();
		cpu_relax();
	}

	while (!time_went_backward && get_tb() - start < tb_hz*2) {
		check_and_record_time();
		udelay(1);
	}

	if (machine_is_powernv()) {
		while (!time_went_backward && get_tb() - start < tb_hz*2) {
			check_and_record_time();
			update_time(0x1234000000);
			cpu_relax();
			update_time(-0x1234000000);
		}
	}
}

static void test_time_sync(int argc, char **argv)
{
	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	if (nr_cpus_present < 2) {
		report_skip("Requires SMP (2 or more CPUs)");
		return;
	}

	time_went_backward = false;

	if (!start_all_cpus(time_sync_fn))
		report_abort("Failed to start secondary cpus");

	time_sync_fn(-1);

	stop_all_cpus();

	report(!time_went_backward, "time sync");
}

static volatile bool relax_test_running = true;

static int relax_loop_count[NR_CPUS];

static void relax_fn(int cpu_id)
{
	volatile int i = 0;

	while (relax_test_running) {
		cpu_relax();
		i++;
	}

	relax_loop_count[cpu_id] = i;
}

#define ITERS 1000000

static void test_relax(int argc, char **argv)
{
	volatile int i;
	int count;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	if (nr_cpus_present < 2) {
		report_skip("Requires SMP (2 or more CPUs)");
		return;
	}

	if (!start_all_cpus(relax_fn))
		report_abort("Failed to start secondary cpus");

	for (i = 0; i < ITERS; i++)
		;

	relax_test_running = false;

	stop_all_cpus();

	count = 0;
	for (i = 0; i < NR_CPUS; i++)
		count += relax_loop_count[i];
	if (count == 0)
		count = 1;

	report(true, "busy-loops on CPU:%d vs cpu_relax-loops on others %ld%%", smp_processor_id(), (long)ITERS * 100 / count);
}

static volatile bool pause_test_running = true;

static int pause_loop_count[NR_CPUS];

static void pause_fn(int cpu_id)
{
	volatile int i = 0;

	while (pause_test_running) {
		pause_short();
		i++;
	}

	pause_loop_count[cpu_id] = i;
}

#define ITERS 1000000

static void test_pause(int argc, char **argv)
{
	volatile int i;
	int count;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	if (!cpu_has_pause_short)
		return;

	if (nr_cpus_present < 2) {
		report_skip("Requires SMP (2 or more CPUs)");
		return;
	}

	if (!start_all_cpus(pause_fn))
		report_abort("Failed to start secondary cpus");

	for (i = 0; i < ITERS; i++)
		;

	pause_test_running = false;

	stop_all_cpus();

	count = 0;
	for (i = 0; i < NR_CPUS; i++)
		count += pause_loop_count[i];

	report(true, "busy-loops on CPU:%d vs pause_short-loops on others %ld%%", smp_processor_id(), (long)ITERS * 100 / count);
}

struct {
	const char *name;
	void (*func)(int argc, char **argv);
} hctests[] = {
	{ "start_cpus", test_start_cpus },
	{ "ipi_cpus", test_ipi_cpus },
	{ "time_sync", test_time_sync },
	{ "cpu_relax", test_relax },
	{ "pause", test_pause },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	bool all;
	int i;

	all = argc == 1 || !strcmp(argv[1], "all");

	report_prefix_push("smp");

	for (i = 0; hctests[i].name != NULL; i++) {
		if (all || strcmp(argv[1], hctests[i].name) == 0) {
			report_prefix_push(hctests[i].name);
			hctests[i].func(argc, argv);
			report_prefix_pop();
		}
	}

	report_prefix_pop();
	return report_summary();
}
