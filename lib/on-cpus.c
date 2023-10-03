// SPDX-License-Identifier: GPL-2.0-only
/*
 * on_cpus() support based on cpumasks.
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 */
#include <libcflat.h>
#include <cpumask.h>
#include <on-cpus.h>
#include <asm/barrier.h>
#include <asm/smp.h>

bool cpu0_calls_idle;

struct on_cpu_info {
	void (*func)(void *data);
	void *data;
	cpumask_t waiters;
};
static struct on_cpu_info on_cpu_info[NR_CPUS];
static cpumask_t on_cpu_info_lock;

static bool get_on_cpu_info(int cpu)
{
	return !cpumask_test_and_set_cpu(cpu, &on_cpu_info_lock);
}

static void put_on_cpu_info(int cpu)
{
	int ret = cpumask_test_and_clear_cpu(cpu, &on_cpu_info_lock);
	assert(ret);
}

static void __deadlock_check(int cpu, const cpumask_t *waiters, bool *found)
{
	int i;

	for_each_cpu(i, waiters) {
		if (i == cpu) {
			printf("CPU%d", cpu);
			*found = true;
			return;
		}
		__deadlock_check(cpu, &on_cpu_info[i].waiters, found);
		if (*found) {
			printf(" <=> CPU%d", i);
			return;
		}
	}
}

static void deadlock_check(int me, int cpu)
{
	bool found = false;

	__deadlock_check(cpu, &on_cpu_info[me].waiters, &found);
	if (found) {
		printf(" <=> CPU%d deadlock detectd\n", me);
		assert(0);
	}
}

static void cpu_wait(int cpu)
{
	int me = smp_processor_id();

	if (cpu == me)
		return;

	cpumask_set_cpu(me, &on_cpu_info[cpu].waiters);
	deadlock_check(me, cpu);
	while (!cpu_idle(cpu))
		smp_wait_for_event();
	cpumask_clear_cpu(me, &on_cpu_info[cpu].waiters);
}

void do_idle(void)
{
	int cpu = smp_processor_id();

	if (cpu == 0)
		cpu0_calls_idle = true;

	set_cpu_idle(cpu, true);
	smp_send_event();

	for (;;) {
		while (cpu_idle(cpu))
			smp_wait_for_event();
		smp_rmb();
		on_cpu_info[cpu].func(on_cpu_info[cpu].data);
		on_cpu_info[cpu].func = NULL;
		smp_wmb();
		set_cpu_idle(cpu, true);
		smp_send_event();
	}
}

void on_cpu_async(int cpu, void (*func)(void *data), void *data)
{
	if (cpu == smp_processor_id()) {
		func(data);
		return;
	}

	assert_msg(cpu != 0 || cpu0_calls_idle, "Waiting on CPU0, which is unlikely to idle. "
						"If this is intended set cpu0_calls_idle=1");

	smp_boot_secondary_nofail(cpu, do_idle);

	for (;;) {
		cpu_wait(cpu);
		if (get_on_cpu_info(cpu)) {
			if ((volatile void *)on_cpu_info[cpu].func == NULL)
				break;
			put_on_cpu_info(cpu);
		}
	}

	on_cpu_info[cpu].func = func;
	on_cpu_info[cpu].data = data;
	set_cpu_idle(cpu, false);
	put_on_cpu_info(cpu);
	smp_send_event();
}

void on_cpu(int cpu, void (*func)(void *data), void *data)
{
	on_cpu_async(cpu, func, data);
	cpu_wait(cpu);
}

void on_cpus(void (*func)(void *data), void *data)
{
	int cpu, me = smp_processor_id();

	for_each_present_cpu(cpu) {
		if (cpu == me)
			continue;
		on_cpu_async(cpu, func, data);
	}
	func(data);

	for_each_present_cpu(cpu) {
		if (cpu == me)
			continue;
		cpumask_set_cpu(me, &on_cpu_info[cpu].waiters);
		deadlock_check(me, cpu);
	}
	while (cpumask_weight(&cpu_idle_mask) < nr_cpus - 1)
		smp_wait_for_event();
	for_each_present_cpu(cpu)
		cpumask_clear_cpu(me, &on_cpu_info[cpu].waiters);
}
