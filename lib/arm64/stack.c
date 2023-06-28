// SPDX-License-Identifier: GPL-2.0-only
/*
 * Backtrace support.
 */
#include <libcflat.h>
#include <stdbool.h>
#include <stack.h>

int backtrace_frame(const void *frame, const void **return_addrs, int max_depth)
{
	const void *fp = frame;
	static bool walking;
	void *lr;
	int depth;

	if (walking) {
		printf("RECURSIVE STACK WALK!!!\n");
		return 0;
	}
	walking = true;

	/*
	 * ARM64 stack grows down. fp points to the previous fp on the stack,
	 * and lr is just above it
	 */
	for (depth = 0; fp && depth < max_depth; ++depth) {

		asm volatile ("ldp %0, %1, [%2]"
				  : "=r" (fp), "=r" (lr)
				  : "r" (fp)
				  : );

		return_addrs[depth] = lr;
	}

	walking = false;
	return depth;
}

int backtrace(const void **return_addrs, int max_depth)
{
	return backtrace_frame(__builtin_frame_address(0),
			       return_addrs, max_depth);
}
