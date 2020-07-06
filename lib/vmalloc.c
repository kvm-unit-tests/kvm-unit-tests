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

static struct spinlock lock;
static void *vfree_top = 0;
static void *page_root;

/*
 * Allocate a certain number of pages from the virtual address space (without
 * physical backing).
 *
 * nr is the number of pages to allocate
 * alignment_pages is the alignment of the allocation *in pages*
 */
void *alloc_vpages_aligned(ulong nr, unsigned int align_order)
{
	uintptr_t ptr;

	spin_lock(&lock);
	ptr = (uintptr_t)vfree_top;
	ptr -= PAGE_SIZE * nr;
	ptr &= GENMASK_ULL(63, PAGE_SHIFT + align_order);
	vfree_top = (void *)ptr;
	spin_unlock(&lock);

	/* Cannot return vfree_top here, we are outside the lock! */
	return (void *)ptr;
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
 * Allocate virtual memory, with the specified minimum alignment.
 */
static void *vm_memalign(size_t alignment, size_t size)
{
	phys_addr_t pa;
	void *mem, *p;

	assert(is_power_of_2(alignment));

	size = PAGE_ALIGN(size) / PAGE_SIZE;
	alignment = get_order(PAGE_ALIGN(alignment) / PAGE_SIZE);
	mem = p = alloc_vpages_aligned(size, alignment);
	while (size--) {
		pa = virt_to_phys(alloc_page());
		assert(pa);
		install_page(page_root, pa, p);
		p += PAGE_SIZE;
	}
	return mem;
}

static void vm_free(void *mem, size_t size)
{
	while (size) {
		free_page(phys_to_virt(virt_to_pte_phys(page_root, mem)));
		mem += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
}

static struct alloc_ops vmalloc_ops = {
	.memalign = vm_memalign,
	.free = vm_free,
	.align_min = PAGE_SIZE,
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

void setup_vm()
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
		base = PAGE_ALIGN(base);
		top = top & -PAGE_SIZE;
		free_pages(phys_to_virt(base), top - base);
	}

	find_highmem();
	phys_alloc_get_unused(&base, &top);
	page_root = setup_mmu(top);
	if (base != top) {
		base = PAGE_ALIGN(base);
		top = top & -PAGE_SIZE;
		free_pages(phys_to_virt(base), top - base);
	}

	spin_lock(&lock);
	assert(alloc_ops != &vmalloc_ops);
	alloc_ops = &vmalloc_ops;
	spin_unlock(&lock);
}
