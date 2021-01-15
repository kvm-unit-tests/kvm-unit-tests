/*
 * This work is licensed under the terms of the GNU LGPL, version 2.
 *
 * This is a simple allocator that provides contiguous physical addresses
 * with page granularity.
 */
#include "libcflat.h"
#include "alloc.h"
#include "alloc_phys.h"
#include "alloc_page.h"
#include "bitops.h"
#include "list.h"
#include <asm/page.h>
#include <asm/io.h>
#include <asm/spinlock.h>
#include <asm/memory_areas.h>

#define IS_ALIGNED_ORDER(x,order) IS_ALIGNED((x),BIT_ULL(order))
#define NLISTS ((BITS_PER_LONG) - (PAGE_SHIFT))
#define PFN(x) ((uintptr_t)(x) >> PAGE_SHIFT)

#define ORDER_MASK	0x3f
#define ALLOC_MASK	0x40
#define SPECIAL_MASK	0x80

struct mem_area {
	/* Physical frame number of the first usable frame in the area */
	uintptr_t base;
	/* Physical frame number of the first frame outside the area */
	uintptr_t top;
	/* Combination of SPECIAL_MASK, ALLOC_MASK, and order */
	u8 *page_states;
	/* One freelist for each possible block size, up to NLISTS */
	struct linked_list freelists[NLISTS];
};

static struct mem_area areas[MAX_AREAS];
static unsigned int areas_mask;
static struct spinlock lock;

bool page_alloc_initialized(void)
{
	return areas_mask != 0;
}

static inline bool area_or_metadata_contains(struct mem_area *a, uintptr_t pfn)
{
	return (pfn >= PFN(a->page_states)) && (pfn < a->top);
}

static inline bool area_contains(struct mem_area *a, uintptr_t pfn)
{
	return (pfn >= a->base) && (pfn < a->top);
}

/*
 * Splits the free block starting at addr into 2 blocks of half the size.
 *
 * The function depends on the following assumptions:
 * - The allocator must have been initialized
 * - the block must be within the memory area
 * - all pages in the block must be free and not special
 * - the pointer must point to the start of the block
 * - all pages in the block must have the same block size.
 * - the block size must be greater than 0
 * - the block size must be smaller than the maximum allowed
 * - the block must be in a free list
 * - the function is called with the lock held
 */
static void split(struct mem_area *a, void *addr)
{
	uintptr_t pfn = PFN(addr);
	struct linked_list *p;
	uintptr_t i, idx;
	u8 order;

	assert(a && area_contains(a, pfn));
	idx = pfn - a->base;
	order = a->page_states[idx];
	assert(!(order & ~ORDER_MASK) && order && (order < NLISTS));
	assert(IS_ALIGNED_ORDER(pfn, order));
	assert(area_contains(a, pfn + BIT(order) - 1));

	/* Remove the block from its free list */
	p = list_remove(addr);
	assert(p);

	/* update the block size for each page in the block */
	for (i = 0; i < BIT(order); i++) {
		assert(a->page_states[idx + i] == order);
		a->page_states[idx + i] = order - 1;
	}
	order--;
	/* add the first half block to the appropriate free list */
	list_add(a->freelists + order, p);
	/* add the second half block to the appropriate free list */
	list_add(a->freelists + order, (void *)((pfn + BIT(order)) * PAGE_SIZE));
}

/*
 * Returns a block whose alignment and size are at least the parameter values.
 * If there is not enough free memory, NULL is returned.
 *
 * Both parameters must be not larger than the largest allowed order
 */
static void *page_memalign_order(struct mem_area *a, u8 al, u8 sz)
{
	struct linked_list *p, *res = NULL;
	u8 order;

	assert((al < NLISTS) && (sz < NLISTS));
	/* we need the bigger of the two as starting point */
	order = sz > al ? sz : al;

	/* search all free lists for some memory */
	for ( ; order < NLISTS; order++) {
		p = a->freelists[order].next;
		if (!is_list_empty(p))
			break;
	}
	/* out of memory */
	if (order >= NLISTS)
		return NULL;

	/*
	 * the block is bigger than what we need because either there were
	 * no smaller blocks, or the smaller blocks were not aligned to our
	 * needs; therefore we split the block until we reach the needed size
	 */
	for (; order > sz; order--)
		split(a, p);

	res = list_remove(p);
	memset(a->page_states + (PFN(res) - a->base), ALLOC_MASK | order, BIT(order));
	return res;
}

static struct mem_area *get_area(uintptr_t pfn)
{
	uintptr_t i;

	for (i = 0; i < MAX_AREAS; i++)
		if ((areas_mask & BIT(i)) && area_contains(areas + i, pfn))
			return areas + i;
	return NULL;
}

/*
 * Try to merge two blocks into a bigger one.
 * Returns true in case of a successful merge.
 * Merging will succeed only if both blocks have the same block size and are
 * both free.
 *
 * The function depends on the following assumptions:
 * - the first parameter is strictly smaller than the second
 * - the parameters must point each to the start of their block
 * - the two parameters point to adjacent blocks
 * - the two blocks are both in a free list
 * - all of the pages of the two blocks must be free
 * - all of the pages of the two blocks must have the same block size
 * - the function is called with the lock held
 */
static bool coalesce(struct mem_area *a, u8 order, uintptr_t pfn, uintptr_t pfn2)
{
	uintptr_t first, second, i;
	struct linked_list *li;

	assert(IS_ALIGNED_ORDER(pfn, order) && IS_ALIGNED_ORDER(pfn2, order));
	assert(pfn2 == pfn + BIT(order));
	assert(a);

	/* attempting to coalesce two blocks that belong to different areas */
	if (!area_contains(a, pfn) || !area_contains(a, pfn2 + BIT(order) - 1))
		return false;
	first = pfn - a->base;
	second = pfn2 - a->base;
	/* the two blocks have different sizes, cannot coalesce */
	if ((a->page_states[first] != order) || (a->page_states[second] != order))
		return false;

	/* we can coalesce, remove both blocks from their freelists */
	li = list_remove((void *)(pfn2 << PAGE_SHIFT));
	assert(li);
	li = list_remove((void *)(pfn << PAGE_SHIFT));
	assert(li);
	/* check the metadata entries and update with the new size */
	for (i = 0; i < (2ull << order); i++) {
		assert(a->page_states[first + i] == order);
		a->page_states[first + i] = order + 1;
	}
	/* finally add the newly coalesced block to the appropriate freelist */
	list_add(a->freelists + order + 1, li);
	return true;
}

/*
 * Free a block of memory.
 * The parameter can be NULL, in which case nothing happens.
 *
 * The function depends on the following assumptions:
 * - the parameter is page aligned
 * - the parameter belongs to an existing memory area
 * - the parameter points to the beginning of the block
 * - the size of the block is less than the maximum allowed
 * - the block is completely contained in its memory area
 * - all pages in the block have the same block size
 * - no pages in the memory block were already free
 * - no pages in the memory block are special
 */
static void _free_pages(void *mem)
{
	uintptr_t pfn2, pfn = PFN(mem);
	struct mem_area *a = NULL;
	uintptr_t i, p;
	u8 order;

	if (!mem)
		return;
	assert(IS_ALIGNED((uintptr_t)mem, PAGE_SIZE));

	/* find which area this pointer belongs to*/
	a = get_area(pfn);
	assert_msg(a, "memory does not belong to any area: %p", mem);

	p = pfn - a->base;
	order = a->page_states[p] & ORDER_MASK;

	/* ensure that the first page is allocated and not special */
	assert(a->page_states[p] == (order | ALLOC_MASK));
	/* ensure that the order has a sane value */
	assert(order < NLISTS);
	/* ensure that the block is aligned properly for its size */
	assert(IS_ALIGNED_ORDER(pfn, order));
	/* ensure that the area can contain the whole block */
	assert(area_contains(a, pfn + BIT(order) - 1));

	for (i = 0; i < BIT(order); i++) {
		/* check that all pages of the block have consistent metadata */
		assert(a->page_states[p + i] == (ALLOC_MASK | order));
		/* set the page as free */
		a->page_states[p + i] &= ~ALLOC_MASK;
	}
	/* provisionally add the block to the appropriate free list */
	list_add(a->freelists + order, mem);
	/* try to coalesce the block with neighbouring blocks if possible */
	do {
		/*
		 * get the order again since it might have changed after
		 * coalescing in a previous iteration
		 */
		order = a->page_states[p] & ORDER_MASK;
		/*
		 * let's consider this block and the next one if this block
		 * is aligned to the next size, otherwise let's consider the
		 * previous block and this one
		 */
		if (!IS_ALIGNED_ORDER(pfn, order + 1))
			pfn = pfn - BIT(order);
		pfn2 = pfn + BIT(order);
		/* repeat as long as we manage to coalesce something */
	} while (coalesce(a, order, pfn, pfn2));
}

void free_pages(void *mem)
{
	spin_lock(&lock);
	_free_pages(mem);
	spin_unlock(&lock);
}

static void *_alloc_page_special(uintptr_t addr)
{
	struct mem_area *a;
	uintptr_t mask, i;

	a = get_area(PFN(addr));
	assert(a);
	i = PFN(addr) - a->base;
	if (a->page_states[i] & (ALLOC_MASK | SPECIAL_MASK))
		return NULL;
	while (a->page_states[i]) {
		mask = GENMASK_ULL(63, PAGE_SHIFT + a->page_states[i]);
		split(a, (void *)(addr & mask));
	}
	a->page_states[i] = SPECIAL_MASK;
	return (void *)addr;
}

static void _free_page_special(uintptr_t addr)
{
	struct mem_area *a;
	uintptr_t i;

	a = get_area(PFN(addr));
	assert(a);
	i = PFN(addr) - a->base;
	assert(a->page_states[i] == SPECIAL_MASK);
	a->page_states[i] = ALLOC_MASK;
	_free_pages((void *)addr);
}

void *alloc_pages_special(uintptr_t addr, size_t n)
{
	uintptr_t i;

	assert(IS_ALIGNED(addr, PAGE_SIZE));
	spin_lock(&lock);
	for (i = 0; i < n; i++)
		if (!_alloc_page_special(addr + i * PAGE_SIZE))
			break;
	if (i < n) {
		for (n = 0 ; n < i; n++)
			_free_page_special(addr + n * PAGE_SIZE);
		addr = 0;
	}
	spin_unlock(&lock);
	return (void *)addr;
}

void free_pages_special(uintptr_t addr, size_t n)
{
	uintptr_t i;

	assert(IS_ALIGNED(addr, PAGE_SIZE));
	spin_lock(&lock);
	for (i = 0; i < n; i++)
		_free_page_special(addr + i * PAGE_SIZE);
	spin_unlock(&lock);
}

static void *page_memalign_order_area(unsigned area, u8 ord, u8 al)
{
	void *res = NULL;
	int i;

	spin_lock(&lock);
	area &= areas_mask;
	for (i = 0; !res && (i < MAX_AREAS); i++)
		if (area & BIT(i))
			res = page_memalign_order(areas + i, ord, al);
	spin_unlock(&lock);
	return res;
}

/*
 * Allocates (1 << order) physically contiguous and naturally aligned pages.
 * Returns NULL if the allocation was not possible.
 */
void *alloc_pages_area(unsigned int area, unsigned int order)
{
	return page_memalign_order_area(area, order, order);
}

void *alloc_pages(unsigned int order)
{
	return alloc_pages_area(AREA_ANY, order);
}

/*
 * Allocates (1 << order) physically contiguous aligned pages.
 * Returns NULL if the allocation was not possible.
 */
void *memalign_pages_area(unsigned int area, size_t alignment, size_t size)
{
	assert(is_power_of_2(alignment));
	alignment = get_order(PAGE_ALIGN(alignment) >> PAGE_SHIFT);
	size = get_order(PAGE_ALIGN(size) >> PAGE_SHIFT);
	assert(alignment < NLISTS);
	assert(size < NLISTS);
	return page_memalign_order_area(area, size, alignment);
}

void *memalign_pages(size_t alignment, size_t size)
{
	return memalign_pages_area(AREA_ANY, alignment, size);
}

/*
 * Allocates one page
 */
void *alloc_page()
{
	return alloc_pages(0);
}

static struct alloc_ops page_alloc_ops = {
	.memalign = memalign_pages,
	.free = free_pages,
	.align_min = PAGE_SIZE,
};

/*
 * Enables the page allocator.
 *
 * Prerequisites:
 * - at least one memory area has been initialized
 */
void page_alloc_ops_enable(void)
{
	spin_lock(&lock);
	assert(page_alloc_initialized());
	alloc_ops = &page_alloc_ops;
	spin_unlock(&lock);
}

/*
 * Adds a new memory area to the pool of available memory.
 *
 * Prerequisites:
 * - the lock is held
 * - start and top are page frame numbers
 * - start is smaller than top
 * - top does not fall outside of addressable memory
 * - there is at least one more slot free for memory areas
 * - if a specific memory area number has been indicated, it needs to be free
 * - the memory area to add does not overlap with existing areas
 * - the memory area to add has at least 5 pages available
 */
static void _page_alloc_init_area(u8 n, uintptr_t start_pfn, uintptr_t top_pfn)
{
	size_t table_size, npages, i;
	struct mem_area *a;
	u8 order = 0;

	/* the number must be within the allowed range */
	assert(n < MAX_AREAS);
	/* the new area number must be unused */
	assert(!(areas_mask & BIT(n)));

	/* other basic sanity checks */
	assert(top_pfn > start_pfn);
	assert(top_pfn - start_pfn > 4);
	assert(top_pfn < BIT_ULL(sizeof(void *) * 8 - PAGE_SHIFT));

	/* calculate the size of the metadata table in pages */
	table_size = (top_pfn - start_pfn + PAGE_SIZE) / (PAGE_SIZE + 1);

	/* fill in the values of the new area */
	a = areas + n;
	a->page_states = (void *)(start_pfn << PAGE_SHIFT);
	a->base = start_pfn + table_size;
	a->top = top_pfn;
	npages = top_pfn - a->base;
	assert((a->base - start_pfn) * PAGE_SIZE >= npages);

	/* check that the new area does not overlap with any existing areas */
	for (i = 0; i < MAX_AREAS; i++) {
		if (!(areas_mask & BIT(i)))
			continue;
		assert(!area_or_metadata_contains(areas + i, start_pfn));
		assert(!area_or_metadata_contains(areas + i, top_pfn - 1));
		assert(!area_or_metadata_contains(a, PFN(areas[i].page_states)));
		assert(!area_or_metadata_contains(a, areas[i].top - 1));
	}
	/* initialize all freelists for the new area */
	for (i = 0; i < NLISTS; i++)
		a->freelists[i].next = a->freelists[i].prev = a->freelists + i;

	/* initialize the metadata for the available memory */
	for (i = a->base; i < a->top; i += 1ull << order) {
		/* search which order to start from */
		while (i + BIT(order) > a->top) {
			assert(order);
			order--;
		}
		/*
		 * we need both loops, one for the start and the other for
		 * the end of the block, in case it spans a power of two
		 * boundary
		 */
		while (IS_ALIGNED_ORDER(i, order + 1) && (i + BIT(order + 1) <= a->top))
			order++;
		assert(order < NLISTS);
		/* initialize the metadata and add to the freelist */
		memset(a->page_states + (i - a->base), order, BIT(order));
		list_add(a->freelists + order, (void *)(i << PAGE_SHIFT));
	}
	/* finally mark the area as present */
	areas_mask |= BIT(n);
}

static void __page_alloc_init_area(u8 n, uintptr_t cutoff, uintptr_t base_pfn, uintptr_t *top_pfn)
{
	if (*top_pfn > cutoff) {
		spin_lock(&lock);
		if (base_pfn >= cutoff) {
			_page_alloc_init_area(n, base_pfn, *top_pfn);
			*top_pfn = 0;
		} else {
			_page_alloc_init_area(n, cutoff, *top_pfn);
			*top_pfn = cutoff;
		}
		spin_unlock(&lock);
	}
}

/*
 * Adds a new memory area to the pool of available memory.
 *
 * Prerequisites:
 * see _page_alloc_init_area
 */
void page_alloc_init_area(u8 n, uintptr_t base_pfn, uintptr_t top_pfn)
{
	if (n != AREA_ANY_NUMBER) {
		__page_alloc_init_area(n, 0, base_pfn, &top_pfn);
		return;
	}
#ifdef AREA_HIGH_PFN
	__page_alloc_init_area(AREA_HIGH_NUMBER, AREA_HIGH_PFN, base_pfn, &top_pfn);
#endif
	__page_alloc_init_area(AREA_NORMAL_NUMBER, AREA_NORMAL_PFN, base_pfn, &top_pfn);
#ifdef AREA_LOW_PFN
	__page_alloc_init_area(AREA_LOW_NUMBER, AREA_LOW_PFN, base_pfn, &top_pfn);
#endif
#ifdef AREA_LOWEST_PFN
	__page_alloc_init_area(AREA_LOWEST_NUMBER, AREA_LOWEST_PFN, base_pfn, &top_pfn);
#endif
}
