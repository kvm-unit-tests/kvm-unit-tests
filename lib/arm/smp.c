/*
 * Secondary cpu support
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/thread_info.h>
#include <asm/spinlock.h>
#include <asm/cpumask.h>
#include <asm/barrier.h>
#include <asm/mmu.h>
#include <asm/psci.h>
#include <asm/smp.h>

cpumask_t cpu_present_mask;
cpumask_t cpu_online_mask;
cpumask_t cpu_idle_mask;

struct secondary_data {
	void *stack;            /* must be first member of struct */
	secondary_entry_fn entry;
};
struct secondary_data secondary_data;
static struct spinlock lock;

secondary_entry_fn secondary_cinit(void)
{
	struct thread_info *ti = current_thread_info();
	secondary_entry_fn entry;

	thread_info_init(ti, 0);
	mmu_mark_enabled(ti->cpu);

	/*
	 * Save secondary_data.entry locally to avoid opening a race
	 * window between marking ourselves online and calling it.
	 */
	entry = secondary_data.entry;
	set_cpu_online(ti->cpu, true);
	sev();

	/*
	 * Return to the assembly stub, allowing entry to be called
	 * from there with an empty stack.
	 */
	return entry;
}

static void __smp_boot_secondary(int cpu, secondary_entry_fn entry)
{
	int ret;

	secondary_data.stack = thread_stack_alloc();
	secondary_data.entry = entry;
	mmu_mark_disabled(cpu);
	ret = cpu_psci_cpu_boot(cpu);
	assert(ret == 0);

	while (!cpu_online(cpu))
		wfe();
}

void smp_boot_secondary(int cpu, secondary_entry_fn entry)
{
	spin_lock(&lock);
	assert_msg(!cpu_online(cpu), "CPU%d already boot once", cpu);
	__smp_boot_secondary(cpu, entry);
	spin_unlock(&lock);
}

typedef void (*on_cpu_func)(void *);
struct on_cpu_info {
	on_cpu_func func;
	void *data;
};
static struct on_cpu_info on_cpu_info[NR_CPUS];

void do_idle(void)
{
	int cpu = smp_processor_id();

	set_cpu_idle(cpu, true);
	sev();

	for (;;) {
		while (cpu_idle(cpu))
			wfe();
		smp_rmb();
		on_cpu_info[cpu].func(on_cpu_info[cpu].data);
		on_cpu_info[cpu].func = NULL;
		smp_wmb();
		set_cpu_idle(cpu, true);
		sev();
	}
}

void on_cpu_async(int cpu, void (*func)(void *data), void *data)
{
	if (cpu == smp_processor_id()) {
		func(data);
		return;
	}

	spin_lock(&lock);
	if (!cpu_online(cpu))
		__smp_boot_secondary(cpu, do_idle);
	spin_unlock(&lock);

	for (;;) {
		while (!cpu_idle(cpu))
			wfe();
		spin_lock(&lock);
		if ((volatile void *)on_cpu_info[cpu].func == NULL)
			break;
		spin_unlock(&lock);
	}
	on_cpu_info[cpu].func = func;
	on_cpu_info[cpu].data = data;
	spin_unlock(&lock);
	set_cpu_idle(cpu, false);
	sev();
}

void on_cpu(int cpu, void (*func)(void *data), void *data)
{
	on_cpu_async(cpu, func, data);

	while (!cpu_idle(cpu))
		wfe();
}

void on_cpus(void (*func)(void))
{
	int cpu;

	for_each_present_cpu(cpu) {
		if (cpu == 0)
			continue;
		on_cpu_async(cpu, (on_cpu_func)func, NULL);
	}
	func();

	set_cpu_idle(0, true);
	while (!cpumask_full(&cpu_idle_mask))
		wfe();
	set_cpu_idle(0, false);
}
