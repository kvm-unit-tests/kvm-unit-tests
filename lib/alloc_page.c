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

#define ORDER_MASK		0x3f
#define STATUS_MASK		0xc0

#define STATUS_FRESH		0x00
#define STATUS_FREE		0x40
#define STATUS_ALLOCATED	0x80
#define STATUS_SPECIAL		0xc0

#define IS_FRESH(x)	(((x) & STATUS_MASK) == STATUS_FRESH)
#define IS_FREE(x)	(((x) & STATUS_MASK) == STATUS_FREE)
#define IS_ALLOCATED(x)	(((x) & STATUS_MASK) == STATUS_ALLOCATED)
#define IS_SPECIAL(x)	(((x) & STATUS_MASK) == STATUS_SPECIAL)

#define IS_USABLE(x)	(IS_FREE(x) || IS_FRESH(x))

typedef phys_addr_t pfn_t;

struct mem_area {
	/* Physical frame number of the first usable frame in the area */
	pfn_t base;
	/* Physical frame number of the first frame outside the area */
	pfn_t top;
	/* Per page metadata, each entry is a combination *_MASK and order */
	u8 *page_states;
	/* Highest block order available in this area */
	u8 max_order;
	/* One freelist for each possible block size, up to NLISTS */
	struct linked_list freelists[NLISTS];
};

/* Descriptors for each possible area */
static struct mem_area areas[MAX_AREAS];
/* Mask of initialized areas */
static unsigned int areas_mask;
/* Protects areas and areas mask */
static struct spinlock lock;

bool page_alloc_initialized(void)
{
	return areas_mask != 0;
}

/*
 * Each memory area contains an array of metadata entries at the very
 * beginning. The usable memory follows immediately afterwards.
 * This function returns true if the given pfn falls anywhere within the
 * memory area, including the metadata area.
 */
static inline bool area_contains_pfn(struct mem_area *a, pfn_t pfn)
{
	return (pfn >= virt_to_pfn(a->page_states)) && (pfn < a->top);
}

/*
 * Each memory area contains an array of metadata entries at the very
 * beginning. The usable memory follows immediately afterwards.
 * This function returns true if the given pfn falls in the usable range of
 * the given memory area.
 */
static inline bool usable_area_contains_pfn(struct mem_area *a, pfn_t pfn)
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
	pfn_t i, idx, pfn = virt_to_pfn(addr);
	u8 metadata, order;

	assert(a && usable_area_contains_pfn(a, pfn));
	idx = pfn - a->base;
	metadata = a->page_states[idx];
	order = metadata & ORDER_MASK;
	assert(IS_USABLE(metadata) && order && (order < NLISTS));
	assert(IS_ALIGNED_ORDER(pfn, order));
	assert(usable_area_contains_pfn(a, pfn + BIT(order) - 1));

	/* Remove the block from its free list */
	list_remove(addr);

	/* update the block size for each page in the block */
	for (i = 0; i < BIT(order); i++) {
		assert(a->page_states[idx + i] == metadata);
		a->page_states[idx + i] = metadata - 1;
	}
	if ((order == a->max_order) && (is_list_empty(a->freelists + order)))
		a->max_order--;
	order--;

	/* add the two half blocks to the appropriate free list */
	if (IS_FRESH(metadata)) {
		/* add to the tail if the blocks are fresh */
		list_add_tail(a->freelists + order, addr);
		list_add_tail(a->freelists + order, pfn_to_virt(pfn + BIT(order)));
	} else {
		/* add to the front if the blocks are dirty */
		list_add(a->freelists + order, addr);
		list_add(a->freelists + order, pfn_to_virt(pfn + BIT(order)));
	}
}

/*
 * Returns a block whose alignment and size are at least the parameter values.
 * If there is not enough free memory, NULL is returned.
 *
 * Both parameters must be not larger than the largest allowed order
 */
static void *page_memalign_order(struct mem_area *a, u8 al, u8 sz, bool fresh)
{
	struct linked_list *p;
	pfn_t idx;
	u8 order;

	assert((al < NLISTS) && (sz < NLISTS));
	/* we need the bigger of the two as starting point */
	order = sz > al ? sz : al;
	/*
	 * we need to go one order up if we want a completely fresh block,
	 * since the first page contains the freelist pointers, and
	 * therefore it is always dirty
	 */
	order += fresh;

	/* search all free lists for some memory */
	for ( ; order <= a->max_order; order++) {
		p = fresh ? a->freelists[order].prev : a->freelists[order].next;
		if (is_list_empty(p))
			continue;
		idx = virt_to_pfn(p) - a->base;
		if (fresh && !IS_FRESH(a->page_states[idx]))
			continue;
		break;
	}

	/* out of memory */
	if (order > a->max_order)
		return NULL;

	/*
	 * the block is bigger than what we need because either there were
	 * no smaller blocks, or the smaller blocks were not aligned to our
	 * needs; therefore we split the block until we reach the needed size
	 */
	for (; order > sz; order--)
		split(a, p);

	list_remove(p);
	/* We now have a block twice the size, but the first page is dirty. */
	if (fresh) {
		order--;
		/* Put back the first (partially dirty) half of the block */
		memset(a->page_states + idx, STATUS_FRESH | order, BIT(order));
		list_add_tail(a->freelists + order, p);
		idx += BIT(order);
		p = pfn_to_virt(a->base + idx);
	}
	memset(a->page_states + idx, STATUS_ALLOCATED | order, BIT(order));
	return p;
}

static struct mem_area *get_area(pfn_t pfn)
{
	uintptr_t i;

	for (i = 0; i < MAX_AREAS; i++)
		if ((areas_mask & BIT(i)) && usable_area_contains_pfn(areas + i, pfn))
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
static bool coalesce(struct mem_area *a, u8 order, pfn_t pfn, pfn_t pfn2)
{
	pfn_t first, second, i;

	assert(IS_ALIGNED_ORDER(pfn, order) && IS_ALIGNED_ORDER(pfn2, order));
	assert(pfn2 == pfn + BIT(order));
	assert(a);

	/* attempting to coalesce two blocks that belong to different areas */
	if (!usable_area_contains_pfn(a, pfn) || !usable_area_contains_pfn(a, pfn2 + BIT(order) - 1))
		return false;
	first = pfn - a->base;
	second = pfn2 - a->base;
	/* the two blocks have different sizes, cannot coalesce */
	if ((a->page_states[first] != order) || (a->page_states[second] != order))
		return false;

	/* we can coalesce, remove both blocks from their freelists */
	list_remove(pfn_to_virt(pfn2));
	list_remove(pfn_to_virt(pfn));
	/* check the metadata entries and update with the new size */
	for (i = 0; i < (2ull << order); i++) {
		assert(a->page_states[first + i] == order);
		a->page_states[first + i] = order + 1;
	}
	/* finally add the newly coalesced block to the appropriate freelist */
	list_add(a->freelists + order + 1, pfn_to_virt(pfn));
	if (order + 1 > a->max_order)
		a->max_order = order + 1;
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
	pfn_t pfn2, pfn = virt_to_pfn(mem);
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
	assert(IS_ALLOCATED(a->page_states[p]));
	/* ensure that the order has a sane value */
	assert(order < NLISTS);
	/* ensure that the block is aligned properly for its size */
	assert(IS_ALIGNED_ORDER(pfn, order));
	/* ensure that the area can contain the whole block */
	assert(usable_area_contains_pfn(a, pfn + BIT(order) - 1));

	for (i = 0; i < BIT(order); i++) {
		/* check that all pages of the block have consistent metadata */
		assert(a->page_states[p + i] == (STATUS_ALLOCATED | order));
		/* set the page as free */
		a->page_states[p + i] = STATUS_FREE | order;
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

static int _reserve_one_page(pfn_t pfn)
{
	struct mem_area *a;
	pfn_t mask, i;

	a = get_area(pfn);
	if (!a)
		return -1;
	i = pfn - a->base;
	if (!IS_USABLE(a->page_states[i]))
		return -1;
	while (a->page_states[i]) {
		mask = GENMASK_ULL(63, a->page_states[i]);
		split(a, pfn_to_virt(pfn & mask));
	}
	a->page_states[i] = STATUS_SPECIAL;
	return 0;
}

static void _unreserve_one_page(pfn_t pfn)
{
	struct mem_area *a;
	pfn_t i;

	a = get_area(pfn);
	assert(a);
	i = pfn - a->base;
	assert(a->page_states[i] == STATUS_SPECIAL);
	a->page_states[i] = STATUS_ALLOCATED;
	_free_pages(pfn_to_virt(pfn));
}

int reserve_pages(phys_addr_t addr, size_t n)
{
	pfn_t pfn;
	size_t i;

	assert(IS_ALIGNED(addr, PAGE_SIZE));
	pfn = addr >> PAGE_SHIFT;
	spin_lock(&lock);
	for (i = 0; i < n; i++)
		if (_reserve_one_page(pfn + i))
			break;
	if (i < n) {
		for (n = 0 ; n < i; n++)
			_unreserve_one_page(pfn + n);
		n = 0;
	}
	spin_unlock(&lock);
	return -!n;
}

void unreserve_pages(phys_addr_t addr, size_t n)
{
	pfn_t pfn;
	size_t i;

	assert(IS_ALIGNED(addr, PAGE_SIZE));
	pfn = addr >> PAGE_SHIFT;
	spin_lock(&lock);
	for (i = 0; i < n; i++)
		_unreserve_one_page(pfn + i);
	spin_unlock(&lock);
}

static void *page_memalign_order_flags(u8 al, u8 ord, u32 flags)
{
	void *res = NULL;
	int i, area, fresh;

	fresh = !!(flags & FLAG_FRESH);
	spin_lock(&lock);
	area = (flags & AREA_MASK) ? flags & areas_mask : areas_mask;
	for (i = 0; !res && (i < MAX_AREAS); i++)
		if (area & BIT(i))
			res = page_memalign_order(areas + i, al, ord, fresh);
	spin_unlock(&lock);
	if (res && !(flags & FLAG_DONTZERO))
		memset(res, 0, BIT(ord) * PAGE_SIZE);
	return res;
}

/*
 * Allocates (1 << order) physically contiguous and naturally aligned pages.
 * Returns NULL if the allocation was not possible.
 */
void *alloc_pages_flags(unsigned int order, unsigned int flags)
{
	return page_memalign_order_flags(order, order, flags);
}

/*
 * Allocates (1 << order) physically contiguous aligned pages.
 * Returns NULL if the allocation was not possible.
 */
void *memalign_pages_flags(size_t alignment, size_t size, unsigned int flags)
{
	assert(is_power_of_2(alignment));
	alignment = get_order(PAGE_ALIGN(alignment) >> PAGE_SHIFT);
	size = get_order(PAGE_ALIGN(size) >> PAGE_SHIFT);
	assert(alignment < NLISTS);
	assert(size < NLISTS);
	return page_memalign_order_flags(alignment, size, flags);
}


static struct alloc_ops page_alloc_ops = {
	.memalign = memalign_pages,
	.free = free_pages,
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
static void _page_alloc_init_area(u8 n, pfn_t start_pfn, pfn_t top_pfn)
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
	a->page_states = pfn_to_virt(start_pfn);
	a->base = start_pfn + table_size;
	a->top = top_pfn;
	a->max_order = 0;
	npages = top_pfn - a->base;
	assert((a->base - start_pfn) * PAGE_SIZE >= npages);

	/* check that the new area does not overlap with any existing areas */
	for (i = 0; i < MAX_AREAS; i++) {
		if (!(areas_mask & BIT(i)))
			continue;
		assert(!area_contains_pfn(areas + i, start_pfn));
		assert(!area_contains_pfn(areas + i, top_pfn - 1));
		assert(!area_contains_pfn(a, virt_to_pfn(areas[i].page_states)));
		assert(!area_contains_pfn(a, areas[i].top - 1));
	}
	/* initialize all freelists for the new area */
	for (i = 0; i < NLISTS; i++)
		a->freelists[i].prev = a->freelists[i].next = a->freelists + i;

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
		memset(a->page_states + (i - a->base), STATUS_FRESH | order, BIT(order));
		list_add(a->freelists + order, pfn_to_virt(i));
		if (order > a->max_order)
			a->max_order = order;
	}
	/* finally mark the area as present */
	areas_mask |= BIT(n);
}

static void __page_alloc_init_area(u8 n, pfn_t cutoff, pfn_t base_pfn, pfn_t *top_pfn)
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
void page_alloc_init_area(u8 n, phys_addr_t base_pfn, phys_addr_t top_pfn)
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
