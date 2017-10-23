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
#include "alloc_phys.h"
#include "alloc_page.h"
#include "vmalloc.h"

static struct spinlock lock;
static void *vfree_top = 0;
static void *page_root;

void *alloc_vpages(ulong nr)
{
	spin_lock(&lock);
	vfree_top -= PAGE_SIZE * nr;
	spin_unlock(&lock);
	return vfree_top;
}

void *alloc_vpage(void)
{
	return alloc_vpages(1);
}

void init_alloc_vpage(void *top)
{
	vfree_top = top;
}

void setup_vm()
{
	phys_addr_t base, top;
	phys_alloc_get_unused(&base, &top);
	base = (base + PAGE_SIZE - 1) & -PAGE_SIZE;
	top = top & -PAGE_SIZE;
	free_pages(phys_to_virt(base), top - base);
	page_root = setup_mmu(top);
}
