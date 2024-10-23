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
	void *sp_mem = __va(cpus[cpu].sp);
	struct secondary_data *data;
	struct sbiret ret;

	if (!sp_mem) {
		phys_addr_t sp_phys;

		sp_mem = alloc_pages(1) + SZ_8K - 16;
		sp_phys = virt_to_phys(sp_mem);
		cpus[cpu].sp = __pa(sp_phys);

		assert(__va(cpus[cpu].sp) == sp_mem);
	}

	sp_mem -= sizeof(struct secondary_data);
	data = (struct secondary_data *)sp_mem;
	data->satp = csr_read(CSR_SATP);
	data->stvec = csr_read(CSR_STVEC);
	data->func = func;

	ret = sbi_hart_start(cpus[cpu].hartid, __pa(secondary_entry), cpus[cpu].sp);
	assert(ret.error == SBI_SUCCESS);
}

void smp_boot_secondary(int cpu, void (*func)(void))
{
	struct sbiret ret;

	do {
		ret = sbi_hart_get_status(cpus[cpu].hartid);
		assert(!ret.error);
	} while (ret.value == SBI_EXT_HSM_STOP_PENDING);

	assert_msg(ret.value == SBI_EXT_HSM_STOPPED, "CPU%d is not stopped", cpu);
	__smp_boot_secondary(cpu, func);

	while (!cpu_online(cpu))
		smp_wait_for_event();
}

void smp_boot_secondary_nofail(int cpu, void (*func)(void))
{
	struct sbiret ret;

	do {
		ret = sbi_hart_get_status(cpus[cpu].hartid);
		assert(!ret.error);
	} while (ret.value == SBI_EXT_HSM_STOP_PENDING);

	if (ret.value == SBI_EXT_HSM_STOPPED)
		__smp_boot_secondary(cpu, func);
	else
		assert_msg(ret.value == SBI_EXT_HSM_START_PENDING || ret.value == SBI_EXT_HSM_STARTED,
			   "CPU%d is in an unexpected state %ld", cpu, ret.value);

	while (!cpu_online(cpu))
		smp_wait_for_event();
}
