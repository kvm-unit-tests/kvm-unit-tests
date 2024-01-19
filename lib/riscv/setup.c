// SPDX-License-Identifier: GPL-2.0-only
/*
 * Initialize machine setup information and I/O.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc.h>
#include <alloc_page.h>
#include <alloc_phys.h>
#include <argv.h>
#include <cpumask.h>
#include <devicetree.h>
#include <memregions.h>
#include <on-cpus.h>
#include <asm/csr.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/setup.h>

#define VA_BASE			((phys_addr_t)3 * SZ_1G)

#define MAX_DT_MEM_REGIONS	16
#define NR_MEM_REGIONS		(MAX_DT_MEM_REGIONS + 16)

char *initrd;
u32 initrd_size;

struct thread_info cpus[NR_CPUS];
int nr_cpus;

static struct mem_region riscv_mem_regions[NR_MEM_REGIONS + 1];

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

extern unsigned long _etext;

static void mem_init(phys_addr_t freemem_start)
{
	struct mem_region *freemem, *code, *data;
	phys_addr_t freemem_end, base, top;

	memregions_init(riscv_mem_regions, NR_MEM_REGIONS);
	memregions_add_dt_regions(MAX_DT_MEM_REGIONS);

	/* Split the region with the code into two regions; code and data */
	memregions_split((unsigned long)&_etext, &code, &data);
	assert(code);
	code->flags |= MR_F_CODE;

	freemem = memregions_find(freemem_start);
	assert(freemem && !(freemem->flags & (MR_F_IO | MR_F_CODE)));

	freemem_end = freemem->end & PAGE_MASK;

	/*
	 * The assert below is mostly checking that the free memory doesn't
	 * start in the 3G-4G range, which is reserved for virtual addresses,
	 * but it also confirms that there is some free memory (the amount
	 * is arbitrarily selected, but should be sufficient for a unit test)
	 *
	 * TODO: Allow the VA range to shrink and move.
	 */
	if (freemem_end > VA_BASE)
		freemem_end = VA_BASE;
	assert(freemem_end - freemem_start >= SZ_1M * 16);

	/*
	 * TODO: Remove the need for this phys allocator dance, since, as we
	 * can see with the assert, we could have gone straight to the page
	 * allocator.
	 */
	phys_alloc_init(freemem_start, freemem_end - freemem_start);
	phys_alloc_set_minimum_alignment(PAGE_SIZE);
	phys_alloc_get_unused(&base, &top);
	assert(base == freemem_start && top == freemem_end);

	page_alloc_init_area(0, freemem_start >> PAGE_SHIFT, freemem_end >> PAGE_SHIFT);
	page_alloc_ops_enable();
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

	assert(sizeof(long) == 8 || freemem_start < VA_BASE);
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
