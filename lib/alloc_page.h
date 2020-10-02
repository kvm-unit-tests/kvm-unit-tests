/*
 * This work is licensed under the terms of the GNU LGPL, version 2.
 *
 * This is a simple allocator that provides contiguous physical addresses
 * with byte granularity.
 */

#ifndef ALLOC_PAGE_H
#define ALLOC_PAGE_H 1

#include <asm/memory_areas.h>

/* Returns true if the page allocator has been initialized */
bool page_alloc_initialized(void);

/*
 * Initializes a memory area.
 * n is the number of the area to initialize
 * base_pfn is the physical frame number of the start of the area to initialize
 * top_pfn is the physical frame number of the first page immediately after
 * the end of the area to initialize
 */
void page_alloc_init_area(u8 n, uintptr_t base_pfn, uintptr_t top_pfn);

/* Enables the page allocator. At least one area must have been initialized */
void page_alloc_ops_enable(void);

/*
 * Allocate aligned memory from the specified areas.
 * areas is a bitmap of allowed areas
 * alignment must be a power of 2
 */
void *memalign_pages_area(unsigned int areas, size_t alignment, size_t size);

/*
 * Allocate aligned memory from any area.
 * Equivalent to memalign_pages_area(~0, alignment, size).
 */
void *memalign_pages(size_t alignment, size_t size);

/*
 * Allocate naturally aligned memory from the specified areas.
 * Equivalent to memalign_pages_area(areas, 1ull << order, 1ull << order).
 */
void *alloc_pages_area(unsigned int areas, unsigned int order);

/*
 * Allocate one page from any area.
 * Equivalent to alloc_pages(0);
 */
void *alloc_page(void);

/*
 * Allocate naturally aligned memory from any area.
 * Equivalent to alloc_pages_area(~0, order);
 */
void *alloc_pages(unsigned int order);

/*
 * Frees a memory block allocated with any of the memalign_pages* or
 * alloc_pages* functions.
 * The pointer must point to the start of the block.
 */
void free_pages(void *mem, size_t size);

/* For backwards compatibility */
static inline void free_page(void *mem)
{
	return free_pages(mem, 1);
}

/* For backwards compatibility */
static inline void free_pages_by_order(void *mem, unsigned int order)
{
	free_pages(mem, 1ull << order);
}

#endif
