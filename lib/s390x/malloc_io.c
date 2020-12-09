/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * I/O page allocation
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *
 * Using this interface provide host access to the allocated pages in
 * case the guest is a protected guest.
 * This is needed for I/O buffers.
 *
 */
#include <libcflat.h>
#include <asm/page.h>
#include <asm/uv.h>
#include <malloc_io.h>
#include <alloc_page.h>
#include <asm/facility.h>
#include <bitops.h>
#include <uv.h>

static int share_pages(void *p, int count)
{
	int i = 0;

	for (i = 0; i < count; i++, p += PAGE_SIZE)
		if (uv_set_shared((unsigned long)p))
			break;
	return i;
}

static void unshare_pages(void *p, int count)
{
	int i;

	for (i = count; i > 0; i--, p += PAGE_SIZE)
		uv_remove_shared((unsigned long)p);
}

void *alloc_io_mem(int size, int flags)
{
	int order = get_order(size >> PAGE_SHIFT);
	void *p;
	int n;

	assert(size);

	p = alloc_pages_flags(order, AREA_DMA31 | flags);
	if (!p || !uv_os_is_guest())
		return p;

	n = share_pages(p, 1 << order);
	if (n == 1 << order)
		return p;

	unshare_pages(p, n);
	free_pages(p);
	return NULL;
}

void free_io_mem(void *p, int size)
{
	int order = get_order(size >> PAGE_SHIFT);

	assert(IS_ALIGNED((uintptr_t)p, PAGE_SIZE));

	if (uv_os_is_guest())
		unshare_pages(p, 1 << order);
	free_pages(p);
}
