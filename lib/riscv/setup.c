// SPDX-License-Identifier: GPL-2.0-only
/*
 * Initialize machine setup information and I/O.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc.h>
#include <alloc_phys.h>
#include <argv.h>
#include <cpumask.h>
#include <devicetree.h>
#include <on-cpus.h>
#include <asm/csr.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/setup.h>

char *initrd;
u32 initrd_size;

struct thread_info cpus[NR_CPUS];
int nr_cpus;

int hartid_to_cpu(unsigned long hartid)
{
	int cpu;

	for_each_present_cpu(cpu)
		if (cpus[cpu].hartid == hartid)
			return cpu;
	return -1;
}

static void cpu_set_fdt(int fdtnode __unused, u64 regval, void *info __unused)
{
	int cpu = nr_cpus++;

	assert_msg(cpu < NR_CPUS, "Number cpus exceeds maximum supported (%d).", NR_CPUS);

	cpus[cpu].cpu = cpu;
	cpus[cpu].hartid = regval;
	set_cpu_present(cpu, true);
}

static void cpu_init_acpi(void)
{
	assert_msg(false, "ACPI not available");
}

static void cpu_init(void)
{
	int ret;

	nr_cpus = 0;
	if (dt_available()) {
		ret = dt_for_each_cpu_node(cpu_set_fdt, NULL);
		assert(ret == 0);
	} else {
		cpu_init_acpi();
	}

	set_cpu_online(hartid_to_cpu(csr_read(CSR_SSCRATCH)), true);
	cpu0_calls_idle = true;
}

static void mem_init(phys_addr_t freemem_start)
{
	//TODO - for now just assume we've got some memory available
	phys_alloc_init(freemem_start, 16 * SZ_1M);
}

static void banner(void)
{
	puts("\n");
	puts("##########################################################################\n");
	puts("#    kvm-unit-tests\n");
	puts("##########################################################################\n");
	puts("\n");
}

void setup(const void *fdt, phys_addr_t freemem_start)
{
	void *freemem;
	const char *bootargs, *tmp;
	u32 fdt_size;
	int ret;

	assert(sizeof(long) == 8 || freemem_start < (3ul << 30));
	freemem = (void *)(unsigned long)freemem_start;

	/* Move the FDT to the base of free memory */
	fdt_size = fdt_totalsize(fdt);
	ret = fdt_move(fdt, freemem, fdt_size);
	assert(ret == 0);
	ret = dt_init(freemem);
	assert(ret == 0);
	freemem += fdt_size;

	/* Move the initrd to the top of the FDT */
	ret = dt_get_initrd(&tmp, &initrd_size);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	if (ret == 0) {
		initrd = freemem;
		memmove(initrd, tmp, initrd_size);
		freemem += initrd_size;
	}

	mem_init(PAGE_ALIGN((unsigned long)freemem));
	cpu_init();
	thread_info_init();
	io_init();

	ret = dt_get_bootargs(&bootargs);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	setup_args_progname(bootargs);

	if (initrd) {
		/* environ is currently the only file in the initrd */
		char *env = malloc(initrd_size);
		memcpy(env, initrd, initrd_size);
		setup_env(env, initrd_size);
	}

	banner();
}
