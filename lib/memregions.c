// SPDX-License-Identifier: GPL-2.0-only
#include <libcflat.h>
#include <devicetree.h>
#include <memregions.h>

static struct mem_region __initial_mem_regions[NR_INITIAL_MEM_REGIONS + 1];
static size_t nr_regions = NR_INITIAL_MEM_REGIONS;

struct mem_region *mem_regions = __initial_mem_regions;

void memregions_init(struct mem_region regions[], size_t nr)
{
	mem_regions = regions;
	nr_regions = nr;
}

struct mem_region *memregions_add(struct mem_region *r)
{
	struct mem_region *r_next = mem_regions;
	int i = 0;

	for (; r_next->end; ++r_next, ++i)
		;
	assert(i < nr_regions);

	*r_next = *r;

	return r_next;
}

struct mem_region *memregions_find(phys_addr_t paddr)
{
	struct mem_region *r;

	for (r = mem_regions; r->end; ++r)
		if (paddr >= r->start && paddr < r->end)
			return r;
	return NULL;
}

uint32_t memregions_get_flags(phys_addr_t paddr)
{
	struct mem_region *r = memregions_find(paddr);

	return r ? r->flags : MR_F_UNKNOWN;
}

void memregions_split(phys_addr_t addr, struct mem_region **r1, struct mem_region **r2)
{
	*r1 = memregions_find(addr);
	assert(*r1);

	if ((*r1)->start == addr) {
		*r2 = *r1;
		*r1 = NULL;
		return;
	}

	*r2 = memregions_add(&(struct mem_region){
		.start = addr,
		.end = (*r1)->end,
		.flags = (*r1)->flags,
	});

	(*r1)->end = addr;
}

void memregions_add_dt_regions(size_t max_nr)
{
	struct dt_pbus_reg regs[max_nr];
	int nr_regs, i;

	nr_regs = dt_get_memory_params(regs, max_nr);
	assert(nr_regs > 0);

	for (i = 0; i < nr_regs; ++i) {
		memregions_add(&(struct mem_region){
			.start = regs[i].addr,
			.end = regs[i].addr + regs[i].size,
		});
	}
}
