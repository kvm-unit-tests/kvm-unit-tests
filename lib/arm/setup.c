/*
 * Initialize machine setup information and I/O.
 *
 * After running setup() unit tests may query how many cpus they have
 * (nr_cpus), how much memory they have (PHYS_END - PHYS_OFFSET), may
 * use dynamic memory allocation (malloc, etc.), printf, and exit.
 * Finally, argc and argv are also ready to be passed to main().
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <libfdt/libfdt.h>
#include <devicetree.h>
#include <alloc.h>
#include <asm/thread_info.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/mmu.h>
#include <asm/smp.h>

extern unsigned long stacktop;
extern void io_init(void);
extern void setup_args_prognam(const char *args);

u32 cpus[NR_CPUS] = { [0 ... NR_CPUS-1] = (~0U) };
int nr_cpus;

struct mem_region mem_regions[NR_MEM_REGIONS];
phys_addr_t __phys_offset, __phys_end;

static void cpu_set(int fdtnode __unused, u32 regval, void *info __unused)
{
	int cpu = nr_cpus++;

	if (cpu >= NR_CPUS) {
		printf("Number cpus exceeds maximum supported (%d).\n",
			NR_CPUS);
		assert(0);
	}
	cpus[cpu] = regval;
	set_cpu_present(cpu, true);
}

static void cpu_init(void)
{
	int ret;

	nr_cpus = 0;
	ret = dt_for_each_cpu_node(cpu_set, NULL);
	assert(ret == 0);
	set_cpu_online(0, true);
}

static void mem_init(phys_addr_t freemem_start)
{
	struct dt_pbus_reg regs[NR_MEM_REGIONS];
	struct mem_region primary, mem = {
		.start = (phys_addr_t)-1,
	};
	int nr_regs, i;

	nr_regs = dt_get_memory_params(regs, NR_MEM_REGIONS);
	assert(nr_regs > 0);

	primary.end = 0;

	for (i = 0; i < nr_regs; ++i) {
		mem_regions[i].start = regs[i].addr;
		mem_regions[i].end = regs[i].addr + regs[i].size;

		/*
		 * pick the region we're in for our primary region
		 */
		if (freemem_start >= mem_regions[i].start
				&& freemem_start < mem_regions[i].end) {
			mem_regions[i].flags |= MR_F_PRIMARY;
			primary = mem_regions[i];
		}

		/*
		 * set the lowest and highest addresses found,
		 * ignoring potential gaps
		 */
		if (mem_regions[i].start < mem.start)
			mem.start = mem_regions[i].start;
		if (mem_regions[i].end > mem.end)
			mem.end = mem_regions[i].end;
	}
	assert(primary.end != 0);
	assert(!(mem.start & ~PHYS_MASK) && !((mem.end - 1) & ~PHYS_MASK));

	__phys_offset = mem.start;	/* PHYS_OFFSET */
	__phys_end = mem.end;		/* PHYS_END */

	phys_alloc_init(freemem_start, primary.end - freemem_start);
	phys_alloc_set_minimum_alignment(SMP_CACHE_BYTES);

	mmu_enable_idmap();
}

void setup(const void *fdt)
{
	const char *bootargs;
	u32 fdt_size;
	int ret;

	/*
	 * Move the fdt to just above the stack. The free memory
	 * then starts just after the fdt.
	 */
	fdt_size = fdt_totalsize(fdt);
	ret = fdt_move(fdt, &stacktop, fdt_size);
	assert(ret == 0);
	ret = dt_init(&stacktop);
	assert(ret == 0);

	mem_init(PAGE_ALIGN((unsigned long)&stacktop + fdt_size));
	io_init();
	cpu_init();

	thread_info_init(current_thread_info(), 0);

	ret = dt_get_bootargs(&bootargs);
	assert(ret == 0);
	setup_args_prognam(bootargs);
}
