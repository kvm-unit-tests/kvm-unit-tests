/*
 * This work is licensed under the terms of the GNU LGPL, version 2.
 *
 * This is a simple allocator that provides contiguous physical addresses
 * with byte granularity.
 */

#ifndef _ALLOC_PAGE_H_
#define _ALLOC_PAGE_H_

#include <stdbool.h>
#include <asm/memory_areas.h>

#define AREA_ANY_NUMBER	0xff

/* The realmode trampoline gets relocated here during bootup. */
#define RM_TRAMPOLINE_ADDR 0

#define AREA_ANY	0x00000
#define AREA_MASK	0x0ffff

#define FLAG_DONTZERO	0x10000
#define FLAG_FRESH	0x20000

/* Returns true if the page allocator has been initialized */
bool page_alloc_initialized(void);

/*
 * Initializes a memory area.
 * n is the number of the area to initialize
 * base_pfn is the physical frame number of the start of the area to initialize
 * top_pfn is the physical frame number of the first page immediately after
 * the end of the area to initialize
 */
void page_alloc_init_area(u8 n, phys_addr_t base_pfn, phys_addr_t top_pfn);

/* Enables the page allocator. At least one area must have been initialized */
void page_alloc_ops_enable(void);

/*
 * Allocate aligned memory with the specified flags.
 * flags is a bitmap of allowed areas and flags.
 * alignment must be a power of 2
 */
void *memalign_pages_flags(size_t alignment, size_t size, unsigned int flags);

/*
 * Allocate aligned memory from any area and with default flags.
 * Equivalent to memalign_pages_flags(alignment, size, AREA_ANY).
 */
static inline void *memalign_pages(size_t alignment, size_t size)
{
	return memalign_pages_flags(alignment, size, AREA_ANY);
}

/*
 * Allocate 1ull << order naturally aligned pages with the specified flags.
 * Equivalent to memalign_pages_flags(1ull << order, 1ull << order, flags).
 */
void *alloc_pages_flags(unsigned int order, unsigned int flags);

/*
 * Allocate 1ull << order naturally aligned pages from any area and with
 * default flags.
 * Equivalent to alloc_pages_flags(order, AREA_ANY);
 */
static inline void *alloc_pages(unsigned int order)
{
	return alloc_pages_flags(order, AREA_ANY);
}

/*
 * Allocate one page from any area and with default flags.
 * Equivalent to alloc_pages(0);
 */
static inline void *alloc_page(void)
{
	return alloc_pages(0);
}

/*
 * Frees a memory block allocated with any of the memalign_pages* or
 * alloc_pages* functions.
 * The pointer must point to the start of the block.
 */
void free_pages(void *mem);

/*
 * Free one page.
 * Equivalent to free_pages(mem).
 */
static inline void free_page(void *mem)
{
	free_pages(mem);
}

/*
 * Free pages by order.
 * Equivalent to free_pages(mem).
 */
static inline void free_pages_by_order(void *mem, unsigned int order)
{
	free_pages(mem);
}

/*
 * Reserves the specified physical memory range if possible.
 * If the specified range cannot be reserved in its entirety, no action is
 * performed and -1 is returned.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int reserve_pages(phys_addr_t addr, size_t npages);

/*
 * Frees a reserved memory range that had been reserved with
 * reserve_pages.
 * The memory range does not need to match a previous allocation
 * exactly, it can also be a subset, in which case only the specified
 * pages will be freed and unreserved.
 */
void unreserve_pages(phys_addr_t addr, size_t npages);

#endif
