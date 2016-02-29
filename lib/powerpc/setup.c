/*
 * Initialize machine setup information and I/O.
 *
 * After running setup() unit tests may query how many cpus they have
 * (nr_cpus), how much memory they have (PHYSICAL_END - PHYSICAL_START),
 * may use dynamic memory allocation (malloc, etc.), printf, and exit.
 * Finally, argc and argv are also ready to be passed to main().
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <libfdt/libfdt.h>
#include <devicetree.h>
#include <alloc.h>
#include <asm/setup.h>
#include <asm/page.h>

extern unsigned long stacktop;
extern void io_init(void);
extern void setup_args(const char *args);

u32 cpus[NR_CPUS] = { [0 ... NR_CPUS-1] = (~0U) };
int nr_cpus;

struct mem_region mem_regions[NR_MEM_REGIONS];
phys_addr_t __physical_start, __physical_end;
unsigned __icache_bytes, __dcache_bytes;

struct cpu_set_params {
	unsigned icache_bytes;
	unsigned dcache_bytes;
};

static void cpu_set(int fdtnode, u32 regval, void *info)
{
	static bool read_common_info = false;
	struct cpu_set_params *params = info;
	int cpu = nr_cpus++;

	if (cpu >= NR_CPUS) {
		printf("Number cpus exceeds maximum supported (%d).\n",
			NR_CPUS);
		assert(0);
	}
	cpus[cpu] = regval;

	if (!read_common_info) {
		const struct fdt_property *prop;
		u32 *data;

		prop = fdt_get_property(dt_fdt(), fdtnode,
					"i-cache-line-size", NULL);
		assert(prop != NULL);
		data = (u32 *)prop->data;
		params->icache_bytes = fdt32_to_cpu(*data);

		prop = fdt_get_property(dt_fdt(), fdtnode,
					"d-cache-line-size", NULL);
		assert(prop != NULL);
		data = (u32 *)prop->data;
		params->dcache_bytes = fdt32_to_cpu(*data);

		read_common_info = true;
	}
}

static void cpu_init(void)
{
	struct cpu_set_params params;
	int ret;

	nr_cpus = 0;
	ret = dt_for_each_cpu_node(cpu_set, &params);
	assert(ret == 0);
	__icache_bytes = params.icache_bytes;
	__dcache_bytes = params.dcache_bytes;
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
//	assert(!(mem.start & ~PHYS_MASK) && !((mem.end - 1) & ~PHYS_MASK));

	__physical_start = mem.start;	/* PHYSICAL_START */
	__physical_end = mem.end;	/* PHYSICAL_END */

	phys_alloc_init(freemem_start, primary.end - freemem_start);
	phys_alloc_set_minimum_alignment(__icache_bytes > __dcache_bytes
					 ? __icache_bytes : __dcache_bytes);
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

	cpu_init();
	mem_init(PAGE_ALIGN((unsigned long)&stacktop + fdt_size));
	io_init();

	ret = dt_get_bootargs(&bootargs);
	assert(ret == 0);
	setup_args(bootargs);
}
