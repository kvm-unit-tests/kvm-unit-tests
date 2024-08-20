/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _MEMREGIONS_H_
#define _MEMREGIONS_H_
#include <libcflat.h>
#include <bitops.h>

#define NR_INITIAL_MEM_REGIONS		8

#define MR_F_IO				BIT(0)
#define MR_F_CODE			BIT(1)
#define MR_F_RESERVED			BIT(2)
#define MR_F_PERSISTENT			BIT(3)
#define MR_F_UNUSED			BIT(4)
#define MR_F_UNKNOWN			BIT(31)

struct mem_region {
	phys_addr_t start;
	phys_addr_t end;
	uint32_t flags;
};

extern struct mem_region *mem_regions;

void memregions_init(struct mem_region regions[], size_t nr);
struct mem_region *memregions_add(struct mem_region *r);
struct mem_region *memregions_find(phys_addr_t paddr);
uint32_t memregions_get_flags(phys_addr_t paddr);
void memregions_split(phys_addr_t addr, struct mem_region **r1, struct mem_region **r2);
void memregions_add_dt_regions(size_t max_nr);

#ifdef CONFIG_EFI
#include <efi.h>
void memregions_efi_init(struct efi_boot_memmap *mem_map, struct mem_region **freemem);
#endif

#endif /* _MEMREGIONS_H_ */
