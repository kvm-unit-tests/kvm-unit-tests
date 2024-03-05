// SPDX-License-Identifier: GPL-2.0-only
#include <libcflat.h>
#include <stack.h>

int arch_backtrace_frame(const void *frame, const void **return_addrs,
			 int max_depth, bool current_frame)
{
	static bool walking;
	const unsigned long *fp = (unsigned long *)frame;
	int depth;

	if (current_frame)
		fp = __builtin_frame_address(0);

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
