/*
 * Copyright (C) 2012, 2017, Red Hat Inc.
 *
 * This allocator provides contiguous physical addresses with page
 * granularity.
 */

#include "libcflat.h"
#include "asm/spinlock.h"
#include "asm/page.h"
#include "asm/io.h"
#include "alloc.h"
#include "alloc_phys.h"
#include "alloc_page.h"
#include <bitops.h>
#include "vmalloc.h"

#define VM_MAGIC 0x7E57C0DE

#define GET_METADATA(x) (((struct metadata *)(x)) - 1)
#define GET_MAGIC(x) (*((unsigned long *)(x) - 1))

struct metadata {
	unsigned long npages;
	unsigned long magic;
};

static struct spinlock lock;
static void *vfree_top = 0;
static void *page_root;

/*
 * Allocate a certain number of pages from the virtual address space (without
 * physical backing).
 *
 * nr is the number of pages to allocate
 * alignment_pages is the alignment of the allocation *in pages*
 * metadata indicates whether an extra (unaligned) page needs to be allocated
 * right before the main (aligned) allocation.
 *
 * The return value points to the first allocated virtual page, which will
 * be the (potentially unaligned) metadata page if the metadata flag is
 * specified.
 */
static void *do_alloc_vpages(ulong nr, unsigned int align_order, bool metadata)
{
	uintptr_t ptr;

	spin_lock(&lock);
	ptr = (uintptr_t)vfree_top;
	ptr -= PAGE_SIZE * nr;
	ptr &= GENMASK_ULL(63, PAGE_SHIFT + align_order);
	if (metadata)
		ptr -= PAGE_SIZE;
	vfree_top = (void *)ptr;
	spin_unlock(&lock);

	/* Cannot return vfree_top here, we are outside the lock! */
	return (void *)ptr;
}

void *alloc_vpages_aligned(ulong nr, unsigned int align_order)
{
	return do_alloc_vpages(nr, align_order, false);
}

void *alloc_vpages(ulong nr)
{
	return alloc_vpages_aligned(nr, 0);
}

void *alloc_vpage(void)
{
	return alloc_vpages(1);
}

void *vmap(phys_addr_t phys, size_t size)
{
	void *mem, *p;
	size_t pages;

	size = PAGE_ALIGN(size);
	pages = size / PAGE_SIZE;
	mem = p = alloc_vpages(pages);

	phys &= ~(unsigned long long)(PAGE_SIZE - 1);
	while (pages--) {
		install_page(page_root, phys, p);
		phys += PAGE_SIZE;
		p += PAGE_SIZE;
	}
	return mem;
}

/*
 * Allocate one page, for an object with specified alignment.
 * The resulting pointer will be aligned to the required alignment, but
 * intentionally not page-aligned.
 * The metadata for single pages allocation is just the magic value,
 * which is placed right before the pointer, like for bigger allocations.
 */
static void *vm_alloc_one_page(size_t alignment)
{
	void *p;

	/* this guarantees that there will be space for the magic value */
	assert(alignment >= sizeof(uintptr_t));
	assert(alignment < PAGE_SIZE);
	p = alloc_vpage();
	install_page(page_root, virt_to_phys(alloc_page()), p);
	p = (void *)((uintptr_t)p + alignment);
	/* write the magic value right before the returned address */
	GET_MAGIC(p) = VM_MAGIC;
	return p;
}

/*
 * Allocate virtual memory, with the specified minimum alignment.
 * If the allocation fits in one page, only one page is allocated. Otherwise
 * enough pages are allocated for the object, plus one to keep metadata
 * information about the allocation.
 */
static void *vm_memalign(size_t alignment, size_t size)
{
	struct metadata *m;
	phys_addr_t pa;
	uintptr_t p;
	void *mem;
	size_t i;

	if (!size)
		return NULL;
	assert(is_power_of_2(alignment));

	if (alignment < sizeof(uintptr_t))
		alignment = sizeof(uintptr_t);
	/* it fits in one page, allocate only one page */
	if (alignment + size <= PAGE_SIZE)
		return vm_alloc_one_page(alignment);
	size = PAGE_ALIGN(size) / PAGE_SIZE;
	alignment = get_order(PAGE_ALIGN(alignment) / PAGE_SIZE);
	mem = do_alloc_vpages(size, alignment, true);
	p = (uintptr_t)mem;
	/* skip the metadata page */
	mem = (void *)(p + PAGE_SIZE);
	/*
	 * time to actually allocate the physical pages to back our virtual
	 * allocation; note that we need to allocate one extra page (for the
	 * metadata), hence the <=
	 */
	for (i = 0; i <= size; i++, p += PAGE_SIZE) {
		pa = virt_to_phys(alloc_page());
		assert(pa);
		install_page(page_root, pa, (void *)p);
	}
	m = GET_METADATA(mem);
	m->npages = size;
	m->magic = VM_MAGIC;
	return mem;
}

static void vm_free(void *mem)
{
	struct metadata *m;
	uintptr_t ptr, page, i;

	if (!mem)
		return;
	/* the pointer is not page-aligned, it was a single-page allocation */
	if (!IS_ALIGNED((uintptr_t)mem, PAGE_SIZE)) {
		assert(GET_MAGIC(mem) == VM_MAGIC);
		page = virt_to_pte_phys(page_root, mem) & PAGE_MASK;
		assert(page);
		free_page(phys_to_virt(page));
		return;
	}

	/* the pointer is page-aligned, it was a multi-page allocation */
	m = GET_METADATA(mem);
	assert(m->magic == VM_MAGIC);
	assert(m->npages > 0);
	assert(m->npages < BIT_ULL(BITS_PER_LONG - PAGE_SHIFT));
	/* free all the pages including the metadata page */
	ptr = (uintptr_t)m & PAGE_MASK;
	for (i = 0 ; i < m->npages + 1; i++, ptr += PAGE_SIZE) {
		page = virt_to_pte_phys(page_root, (void *)ptr) & PAGE_MASK;
		assert(page);
		free_page(phys_to_virt(page));
	}
}

static struct alloc_ops vmalloc_ops = {
	.memalign = vm_memalign,
	.free = vm_free,
};

void __attribute__((__weak__)) find_highmem(void)
{
}

void init_alloc_vpage(void *top)
{
	spin_lock(&lock);
	assert(alloc_ops != &vmalloc_ops);
	vfree_top = top;
	spin_unlock(&lock);
}

void __setup_vm(void *opaque)
{
	phys_addr_t base, top;

	if (alloc_ops == &vmalloc_ops)
		return;

	phys_alloc_get_unused(&base, &top);
	assert(base != top || page_alloc_initialized());
	/*
	 * Give low memory immediately to the page allocator,
	 * so that it can be used to allocate page tables.
	 */
	if (!page_alloc_initialized()) {
		base = PAGE_ALIGN(base) >> PAGE_SHIFT;
		top = top >> PAGE_SHIFT;
		page_alloc_init_area(AREA_ANY_NUMBER, base, top);
		page_alloc_ops_enable();
	}

	find_highmem();
	phys_alloc_get_unused(&base, &top);
	page_root = setup_mmu(top, opaque);
	if (base != top) {
		base = PAGE_ALIGN(base) >> PAGE_SHIFT;
		top = top >> PAGE_SHIFT;
		page_alloc_init_area(AREA_ANY_NUMBER, base, top);
	}

	spin_lock(&lock);
	assert(alloc_ops != &vmalloc_ops);
	alloc_ops = &vmalloc_ops;
	spin_unlock(&lock);
}

void setup_vm(void)
{
	__setup_vm(NULL);
}
