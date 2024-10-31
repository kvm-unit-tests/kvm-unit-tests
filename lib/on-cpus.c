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
#include <asm/spinlock.h>

bool cpu0_calls_idle;

struct on_cpu_info {
	void (*func)(void *data);
	void *data;
	cpumask_t waiters;
};
static struct on_cpu_info on_cpu_info[NR_CPUS];
static struct spinlock lock;

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

	for (;;) {
		set_cpu_idle(cpu, true);
		smp_send_event();

		while (cpu_idle(cpu))
			smp_wait_for_event();
		smp_rmb();
		on_cpu_info[cpu].func(on_cpu_info[cpu].data);
		smp_wmb(); /* pairs with the smp_rmb() in on_cpu() and on_cpumask() */
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
		spin_lock(&lock);
		if (cpu_idle(cpu))
			break;
		spin_unlock(&lock);
	}

	on_cpu_info[cpu].func = func;
	on_cpu_info[cpu].data = data;
	smp_wmb();
	set_cpu_idle(cpu, false);
	spin_unlock(&lock);
	smp_send_event();
}

void on_cpumask_async(const cpumask_t *mask, void (*func)(void *data), void *data)
{
	int cpu, me = smp_processor_id();

	for_each_cpu(cpu, mask) {
		if (cpu == me)
			continue;
		on_cpu_async(cpu, func, data);
	}
	if (cpumask_test_cpu(me, mask))
		func(data);
}

void on_cpumask(const cpumask_t *mask, void (*func)(void *data), void *data)
{
	int cpu, me = smp_processor_id();
	cpumask_t tmp;

	cpumask_copy(&tmp, mask);
	cpumask_clear_cpu(me, &tmp);

	for_each_cpu(cpu, &tmp)
		on_cpu_async(cpu, func, data);
	if (cpumask_test_cpu(me, mask))
		func(data);

	for_each_cpu(cpu, &tmp) {
		cpumask_set_cpu(me, &on_cpu_info[cpu].waiters);
		deadlock_check(me, cpu);
	}
	while (!cpumask_subset(&tmp, &cpu_idle_mask))
		smp_wait_for_event();
	for_each_cpu(cpu, &tmp)
		cpumask_clear_cpu(me, &on_cpu_info[cpu].waiters);
	smp_rmb(); /* pairs with the smp_wmb() in do_idle() */
}

void on_cpu(int cpu, void (*func)(void *data), void *data)
{
	on_cpu_async(cpu, func, data);
	cpu_wait(cpu);
	smp_rmb(); /* pairs with the smp_wmb() in do_idle() */
}

void on_cpus(void (*func)(void *data), void *data)
{
	on_cpumask(&cpu_present_mask, func, data);
}
