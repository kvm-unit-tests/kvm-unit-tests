// SPDX-License-Identifier: GPL-2.0-only
/*
 * Boot secondary CPUs
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc_page.h>
#include <cpumask.h>
#include <asm/csr.h>
#include <asm/io.h>
#include <asm/mmu.h>
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

	__mmu_enable(data->satp);
	thread_info_init();
	local_hart_init();
	info = current_thread_info();
	set_cpu_online(info->cpu, true);
	smp_send_event();

	return data->func;
}

static void __smp_boot_secondary(int cpu, secondary_func_t func)
{
	struct secondary_data *sp = alloc_pages(1) + SZ_8K - 16;
	phys_addr_t sp_phys;
	struct sbiret ret;

	sp -= sizeof(struct secondary_data);
	sp->satp = csr_read(CSR_SATP);
	sp->stvec = csr_read(CSR_STVEC);
	sp->func = func;

	sp_phys = virt_to_phys(sp);
	assert(sp_phys == __pa(sp_phys));

	ret = sbi_hart_start(cpus[cpu].hartid, (unsigned long)&secondary_entry, __pa(sp_phys));
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
