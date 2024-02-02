// SPDX-License-Identifier: GPL-2.0-only
#include <libcflat.h>
#include <stack.h>

int backtrace_frame(const void *frame, const void **return_addrs, int max_depth)
{
	static bool walking;
	const unsigned long *fp = (unsigned long *)frame;
	int depth;

	if (walking) {
		printf("RECURSIVE STACK WALK!!!\n");
		return 0;
	}
	walking = true;

	for (depth = 0; fp && depth < max_depth; ++depth) {
		return_addrs[depth] = (void *)fp[-1];
		if (return_addrs[depth] == 0)
			break;
		fp = (unsigned long *)fp[-2];
	}

	walking = false;
	return depth;
}

int backtrace(const void **return_addrs, int max_depth)
{
	return backtrace_frame(__builtin_frame_address(0),
			       return_addrs, max_depth);
}
