/*
 * Secondary cpu support
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <auxinfo.h>
#include <cpumask.h>
#include <asm/thread_info.h>
#include <asm/spinlock.h>
#include <asm/mmu.h>
#include <asm/psci.h>
#include <asm/smp.h>

cpumask_t cpu_present_mask;
cpumask_t cpu_online_mask;
cpumask_t cpu_idle_mask;

struct secondary_data secondary_data;
static struct spinlock lock;

/* Needed to compile with -Wmissing-prototypes */
secondary_entry_fn secondary_cinit(void);

secondary_entry_fn secondary_cinit(void)
{
	struct thread_info *ti = current_thread_info();
	secondary_entry_fn entry;

	thread_info_init(ti, 0);

	if (!(auxinfo.flags & AUXINFO_MMU_OFF)) {
		ti->pgtable = mmu_idmap;
		mmu_mark_enabled(ti->cpu);
	}

	/*
	 * Save secondary_data.entry locally to avoid opening a race
	 * window between marking ourselves online and calling it.
	 */
	entry = secondary_data.entry;
	set_cpu_online(ti->cpu, true);
	smp_send_event();

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
		smp_wait_for_event();
}

void smp_boot_secondary(int cpu, secondary_entry_fn entry)
{
	spin_lock(&lock);
	assert_msg(!cpu_online(cpu), "CPU%d already boot once", cpu);
	__smp_boot_secondary(cpu, entry);
	spin_unlock(&lock);
}

void smp_boot_secondary_nofail(int cpu, secondary_entry_fn entry)
{
	spin_lock(&lock);
	if (!cpu_online(cpu))
		__smp_boot_secondary(cpu, entry);
	spin_unlock(&lock);
}
