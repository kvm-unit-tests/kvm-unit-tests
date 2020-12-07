/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x stack implementation
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 */
#include <libcflat.h>
#include <stack.h>

int backtrace_frame(const void *frame, const void **return_addrs, int max_depth)
{
	printf("TODO: Implement backtrace_frame(%p, %p, %d) function!\n",
	       frame, return_addrs, max_depth);
	return 0;
}

int backtrace(const void **return_addrs, int max_depth)
{
	printf("TODO: Implement backtrace(%p, %d) function!\n",
	       return_addrs, max_depth);
	return 0;
}
