/*
 * Copyright (C) 2012, 2017, Red Hat Inc.
 *
 * This allocator provides contiguous physical addresses with page
 * granularity.
 */

#include "libcflat.h"
#include "asm/spinlock.h"
#include "asm/page.h"

static struct spinlock lock;
static void *vfree_top = 0;

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
