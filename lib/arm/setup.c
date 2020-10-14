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
#include <argv.h>
#include <asm/thread_info.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <asm/timer.h>

#include "io.h"

#define NR_INITIAL_MEM_REGIONS 16

extern unsigned long stacktop;

struct timer_state __timer_state;

char *initrd;
u32 initrd_size;

u64 cpus[NR_CPUS] = { [0 ... NR_CPUS-1] = (u64)~0 };
int nr_cpus;

static struct mem_region __initial_mem_regions[NR_INITIAL_MEM_REGIONS + 1];
struct mem_region *mem_regions = __initial_mem_regions;
phys_addr_t __phys_offset, __phys_end;

unsigned long dcache_line_size;

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
	/*
	 * DminLine is log2 of the number of words in the smallest cache line; a
	 * word is 4 bytes.
	 */
	dcache_line_size = 1 << (CTR_DMINLINE(get_ctr()) + 2);
}

unsigned int mem_region_get_flags(phys_addr_t paddr)
{
	struct mem_region *r;

	for (r = mem_regions; r->end; ++r) {
		if (paddr >= r->start && paddr < r->end)
			return r->flags;
	}

	return MR_F_UNKNOWN;
}

static void mem_init(phys_addr_t freemem_start)
{
	struct dt_pbus_reg regs[NR_INITIAL_MEM_REGIONS];
	struct mem_region primary, mem = {
		.start = (phys_addr_t)-1,
	};
	phys_addr_t base, top;
	int nr_regs, nr_io = 0, i;

	/*
	 * mach-virt I/O regions:
	 *   - The first 1G (arm/arm64)
	 *   - 512M at 256G (arm64, arm uses highmem=off)
	 *   - 512G at 512G (arm64, arm uses highmem=off)
	 */
	mem_regions[nr_io++] = (struct mem_region){ 0, (1ul << 30), MR_F_IO };
#ifdef __aarch64__
	mem_regions[nr_io++] = (struct mem_region){ (1ul << 38), (1ul << 38) | (1ul << 29), MR_F_IO };
	mem_regions[nr_io++] = (struct mem_region){ (1ul << 39), (1ul << 40), MR_F_IO };
#endif

	nr_regs = dt_get_memory_params(regs, NR_INITIAL_MEM_REGIONS - nr_io);
	assert(nr_regs > 0);

	primary = (struct mem_region){ 0 };

	for (i = 0; i < nr_regs; ++i) {
		struct mem_region *r = &mem_regions[nr_io + i];

		r->start = regs[i].addr;
		r->end = regs[i].addr + regs[i].size;

		/*
		 * pick the region we're in for our primary region
		 */
		if (freemem_start >= r->start && freemem_start < r->end) {
			r->flags |= MR_F_PRIMARY;
			primary = *r;
		}

		/*
		 * set the lowest and highest addresses found,
		 * ignoring potential gaps
		 */
		if (r->start < mem.start)
			mem.start = r->start;
		if (r->end > mem.end)
			mem.end = r->end;
	}
	assert(primary.end != 0);
	assert(!(mem.start & ~PHYS_MASK) && !((mem.end - 1) & ~PHYS_MASK));

	__phys_offset = primary.start;	/* PHYS_OFFSET */
	__phys_end = primary.end;	/* PHYS_END */

	phys_alloc_init(freemem_start, primary.end - freemem_start);
	phys_alloc_set_minimum_alignment(SMP_CACHE_BYTES);

	phys_alloc_get_unused(&base, &top);
	base = PAGE_ALIGN(base);
	top = top & PAGE_MASK;
	assert(sizeof(long) == 8 || !(base >> 32));
	if (sizeof(long) != 8 && (top >> 32) != 0)
		top = ((uint64_t)1 << 32);
	free_pages((void *)(unsigned long)base, top - base);
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

void setup(const void *fdt)
{
	void *freemem = &stacktop;
	const char *bootargs, *tmp;
	u32 fdt_size;
	int ret;

	/*
	 * Before calling mem_init we need to move the fdt and initrd
	 * to safe locations. We move them to construct the memory
	 * map illustrated below:
	 *
	 *    +----------------------+   <-- top of physical memory
	 *    |                      |
	 *    ~                      ~
	 *    |                      |
	 *    +----------------------+   <-- top of initrd
	 *    |                      |
	 *    +----------------------+   <-- top of FDT
	 *    |                      |
	 *    +----------------------+   <-- top of cpu0's stack
	 *    |                      |
	 *    +----------------------+   <-- top of text/data/bss sections,
	 *    |                      |       see arm/flat.lds
	 *    |                      |
	 *    +----------------------+   <-- load address
	 *    |                      |
	 *    +----------------------+
	 */
	fdt_size = fdt_totalsize(fdt);
	ret = fdt_move(fdt, freemem, fdt_size);
	assert(ret == 0);
	ret = dt_init(freemem);
	assert(ret == 0);
	freemem += fdt_size;

	ret = dt_get_initrd(&tmp, &initrd_size);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	if (ret == 0) {
		initrd = freemem;
		memmove(initrd, tmp, initrd_size);
		freemem += initrd_size;
	}

	/* call init functions */
	mem_init(PAGE_ALIGN((unsigned long)freemem));
	cpu_init();

	/* cpu_init must be called before thread_info_init */
	thread_info_init(current_thread_info(), 0);

	/* mem_init must be called before io_init */
	io_init();

	/* finish setup */
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
}
