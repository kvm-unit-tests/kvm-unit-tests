/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x stack implementation
 *
 * Copyright (c) 2017 Red Hat Inc
 * Copyright 2021 IBM Corp
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <stack.h>
#include <asm/arch_def.h>

int backtrace_frame(const void *frame, const void **return_addrs, int max_depth)
{
	int depth = 0;
	struct stack_frame *stack = (struct stack_frame *)frame;

	for (depth = 0; stack && depth < max_depth; depth++) {
		return_addrs[depth] = (void *)stack->grs[8];
		stack = stack->back_chain;
	}

	return depth;
}

int backtrace(const void **return_addrs, int max_depth)
{
	return backtrace_frame(__builtin_frame_address(0),
			       return_addrs, max_depth);
}
