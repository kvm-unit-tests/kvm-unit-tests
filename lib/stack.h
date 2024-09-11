/*
 * Header for stack related functions
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#ifndef _STACK_H_
#define _STACK_H_

#include <libcflat.h>
#include <asm/stack.h>

#ifdef HAVE_ARCH_BACKTRACE_FRAME
extern int arch_backtrace_frame(const void *frame, const void **return_addrs,
				int max_depth, bool current_frame);

static inline int backtrace_frame(const void *frame, const void **return_addrs,
				  int max_depth)
{
	return arch_backtrace_frame(frame, return_addrs, max_depth, false);
}

static inline int backtrace(const void **return_addrs, int max_depth)
{
	return arch_backtrace_frame(NULL, return_addrs, max_depth, true);
}
#else
extern int backtrace(const void **return_addrs, int max_depth);

static inline int backtrace_frame(const void *frame, const void **return_addrs,
				  int max_depth)
{
	return 0;
}
#endif

bool base_address(const void *rebased_addr, unsigned long *addr);

#endif
