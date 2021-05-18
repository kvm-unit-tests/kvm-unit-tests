#ifndef _ASMARM_SETUP_H_
#define _ASMARM_SETUP_H_
/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/page.h>
#include <asm/pgtable-hwdef.h>

#define NR_CPUS			511
extern u64 cpus[NR_CPUS];	/* per-cpu IDs (MPIDRs) */
extern int nr_cpus;

#define MR_F_IO			(1U << 0)
#define MR_F_CODE		(1U << 1)
#define MR_F_UNKNOWN		(1U << 31)

struct mem_region {
	phys_addr_t start;
	phys_addr_t end;
	unsigned int flags;
};
extern struct mem_region *mem_regions;
extern phys_addr_t __phys_offset, __phys_end;

extern struct mem_region *mem_region_find(phys_addr_t paddr);
extern unsigned int mem_region_get_flags(phys_addr_t paddr);

#define PHYS_OFFSET		(__phys_offset)
#define PHYS_END		(__phys_end)

#define L1_CACHE_SHIFT		6
#define L1_CACHE_BYTES		(1 << L1_CACHE_SHIFT)
#define SMP_CACHE_BYTES		L1_CACHE_BYTES

void setup(const void *fdt, phys_addr_t freemem_start);

#endif /* _ASMARM_SETUP_H_ */
