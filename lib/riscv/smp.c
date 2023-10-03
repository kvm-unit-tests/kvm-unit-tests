// SPDX-License-Identifier: GPL-2.0-only
/*
 * Boot secondary CPUs
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc.h>
#include <cpumask.h>
#include <asm/csr.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/smp.h>

cpumask_t cpu_present_mask;
cpumask_t cpu_online_mask;
cpumask_t cpu_idle_mask;

static cpumask_t cpu_started;

secondary_func_t secondary_cinit(struct secondary_data *data)
{
	struct thread_info *info;

	thread_info_init();
	info = current_thread_info();
	set_cpu_online(info->cpu, true);
	smp_send_event();

	return data->func;
}

static void __smp_boot_secondary(int cpu, secondary_func_t func)
{
	struct secondary_data *sp = memalign(16, SZ_8K) + SZ_8K - 16;
	struct sbiret ret;

	sp -= sizeof(struct secondary_data);
	sp->stvec = csr_read(CSR_STVEC);
	sp->func = func;

	ret = sbi_hart_start(cpus[cpu].hartid, (unsigned long)&secondary_entry, __pa(sp));
	assert(ret.error == SBI_SUCCESS);
}

void smp_boot_secondary(int cpu, void (*func)(void))
{
	int ret = cpumask_test_and_set_cpu(cpu, &cpu_started);

	assert_msg(!ret, "CPU%d already boot once", cpu);
	__smp_boot_secondary(cpu, func);

	while (!cpu_online(cpu))
		smp_wait_for_event();
}

void smp_boot_secondary_nofail(int cpu, void (*func)(void))
{
	int ret = cpumask_test_and_set_cpu(cpu, &cpu_started);

	if (!ret)
		__smp_boot_secondary(cpu, func);

	while (!cpu_online(cpu))
		smp_wait_for_event();
}
