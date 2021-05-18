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
#include <alloc_phys.h>
#include <alloc_page.h>
#include <vmalloc.h>
#include <auxinfo.h>
#include <argv.h>
#include <asm/thread_info.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <asm/timer.h>
#include <asm/psci.h>

#include "io.h"

#define MAX_DT_MEM_REGIONS	16
#define NR_EXTRA_MEM_REGIONS	16
#define NR_INITIAL_MEM_REGIONS	(MAX_DT_MEM_REGIONS + NR_EXTRA_MEM_REGIONS)

extern unsigned long etext;

struct timer_state __timer_state;

char *initrd;
u32 initrd_size;

u64 cpus[NR_CPUS] = { [0 ... NR_CPUS-1] = (u64)~0 };
int nr_cpus;

static struct mem_region __initial_mem_regions[NR_INITIAL_MEM_REGIONS + 1];
struct mem_region *mem_regions = __initial_mem_regions;
phys_addr_t __phys_offset, __phys_end;

int mpidr_to_cpu(uint64_t mpidr)
{
	int i;

	for (i = 0; i < nr_cpus; ++i)
		if (cpus[i] == (mpidr & MPIDR_HWID_BITMASK))
			return i;
	return -1;
}

static void cpu_set(int fdtnode __unused, u64 regval, void *info __unused)
{
	int cpu = nr_cpus++;

	assert_msg(cpu < NR_CPUS, "Number cpus exceeds maximum supported (%d).", NR_CPUS);

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

static void mem_region_add(struct mem_region *r)
{
	struct mem_region *r_next = mem_regions;
	int i = 0;

	for (; r_next->end; ++r_next, ++i)
		;
	assert(i < NR_INITIAL_MEM_REGIONS);

	*r_next = *r;
}

static void mem_regions_add_dt_regions(void)
{
	struct dt_pbus_reg regs[MAX_DT_MEM_REGIONS];
	int nr_regs, i;

	nr_regs = dt_get_memory_params(regs, MAX_DT_MEM_REGIONS);
	assert(nr_regs > 0);

	for (i = 0; i < nr_regs; ++i) {
		mem_region_add(&(struct mem_region){
			.start = regs[i].addr,
			.end = regs[i].addr + regs[i].size,
		});
	}
}

struct mem_region *mem_region_find(phys_addr_t paddr)
{
	struct mem_region *r;

	for (r = mem_regions; r->end; ++r)
		if (paddr >= r->start && paddr < r->end)
			return r;
	return NULL;
}

unsigned int mem_region_get_flags(phys_addr_t paddr)
{
	struct mem_region *r = mem_region_find(paddr);
	return r ? r->flags : MR_F_UNKNOWN;
}

static void mem_regions_add_assumed(void)
{
	phys_addr_t code_end = (phys_addr_t)(unsigned long)&etext;
	struct mem_region *r;

	r = mem_region_find(code_end - 1);
	assert(r);

	/* Split the region with the code into two regions; code and data */
	mem_region_add(&(struct mem_region){
		.start = code_end,
		.end = r->end,
	});
	*r = (struct mem_region){
		.start = r->start,
		.end = code_end,
		.flags = MR_F_CODE,
	};

	/*
	 * mach-virt I/O regions:
	 *   - The first 1G (arm/arm64)
	 *   - 512M at 256G (arm64, arm uses highmem=off)
	 *   - 512G at 512G (arm64, arm uses highmem=off)
	 */
	mem_region_add(&(struct mem_region){ 0, (1ul << 30), MR_F_IO });
#ifdef __aarch64__
	mem_region_add(&(struct mem_region){ (1ul << 38), (1ul << 38) | (1ul << 29), MR_F_IO });
	mem_region_add(&(struct mem_region){ (1ul << 39), (1ul << 40), MR_F_IO });
#endif
}

static void mem_init(phys_addr_t freemem_start)
{
	phys_addr_t base, top;
	struct mem_region *freemem, *r, mem = {
		.start = (phys_addr_t)-1,
	};

	freemem = mem_region_find(freemem_start);
	assert(freemem && !(freemem->flags & (MR_F_IO | MR_F_CODE)));

	for (r = mem_regions; r->end; ++r) {
		if (!(r->flags & MR_F_IO)) {
			if (r->start < mem.start)
				mem.start = r->start;
			if (r->end > mem.end)
				mem.end = r->end;
		}
	}
	assert(mem.end && !(mem.start & ~PHYS_MASK));
	mem.end &= PHYS_MASK;

	/* Check for holes */
	r = mem_region_find(mem.start);
	while (r && r->end != mem.end)
		r = mem_region_find(r->end);
	assert(r);

	/* Ensure our selected freemem range is somewhere in our full range */
	assert(freemem_start >= mem.start && freemem->end <= mem.end);

	__phys_offset = mem.start;	/* PHYS_OFFSET */
	__phys_end = mem.end;		/* PHYS_END */

	phys_alloc_init(freemem_start, freemem->end - freemem_start);
	phys_alloc_set_minimum_alignment(SMP_CACHE_BYTES);

	phys_alloc_get_unused(&base, &top);
	base = PAGE_ALIGN(base);
	top = top & PAGE_MASK;
	assert(sizeof(long) == 8 || !(base >> 32));
	if (sizeof(long) != 8 && (top >> 32) != 0)
		top = ((uint64_t)1 << 32);
	page_alloc_init_area(0, base >> PAGE_SHIFT, top >> PAGE_SHIFT);
	page_alloc_ops_enable();
}

static void timer_save_state(void)
{
	const struct fdt_property *prop;
	const void *fdt = dt_fdt();
	int node, len;
	u32 *data;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,armv8-timer");
	assert(node >= 0 || node == -FDT_ERR_NOTFOUND);

	if (node == -FDT_ERR_NOTFOUND) {
		__timer_state.ptimer.irq = -1;
		__timer_state.vtimer.irq = -1;
		return;
	}

	/*
	 * From Linux devicetree timer binding documentation
	 *
	 * interrupts <type irq flags>:
	 *	secure timer irq
	 *	non-secure timer irq		(ptimer)
	 *	virtual timer irq		(vtimer)
	 *	hypervisor timer irq
	 */
	prop = fdt_get_property(fdt, node, "interrupts", &len);
	assert(prop && len == (4 * 3 * sizeof(u32)));

	data = (u32 *)prop->data;
	assert(fdt32_to_cpu(data[3]) == 1 /* PPI */);
	__timer_state.ptimer.irq = fdt32_to_cpu(data[4]);
	__timer_state.ptimer.irq_flags = fdt32_to_cpu(data[5]);
	assert(fdt32_to_cpu(data[6]) == 1 /* PPI */);
	__timer_state.vtimer.irq = fdt32_to_cpu(data[7]);
	__timer_state.vtimer.irq_flags = fdt32_to_cpu(data[8]);
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

	mem_regions_add_dt_regions();
	mem_regions_add_assumed();
	mem_init(PAGE_ALIGN((unsigned long)freemem));

	psci_set_conduit();
	cpu_init();

	/* cpu_init must be called before thread_info_init */
	thread_info_init(current_thread_info(), 0);

	/* mem_init must be called before io_init */
	io_init();

	timer_save_state();

	ret = dt_get_bootargs(&bootargs);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	setup_args_progname(bootargs);

	if (initrd) {
		/* environ is currently the only file in the initrd */
		char *env = malloc(initrd_size);
		memcpy(env, initrd, initrd_size);
		setup_env(env, initrd_size);
	}

	if (!(auxinfo.flags & AUXINFO_MMU_OFF))
		setup_vm();
}
