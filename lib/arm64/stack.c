// SPDX-License-Identifier: GPL-2.0-only
/*
 * Backtrace support.
 */
#include <libcflat.h>
#include <stdbool.h>
#include <stack.h>

extern char vector_stub_start, vector_stub_end;

int backtrace_frame(const void *frame, const void **return_addrs, int max_depth)
{
	const void *fp = frame;
	static bool walking;
	void *lr;
	int depth;
	bool is_exception = false;
	unsigned long addr;

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

		/*
		 * If this is an exception, add 1 to the pointer so when the
		 * pretty_print_stacks script is run it would get the right
		 * address (it deducts 1 to find the call address, but we want
		 * the actual address).
		 */
		if (is_exception)
			return_addrs[depth] += 1;

		/* Check if we are in the exception handlers for the next entry */
		addr = (unsigned long)lr;
		is_exception = (addr >= (unsigned long)&vector_stub_start &&
				addr < (unsigned long)&vector_stub_end);
	}

	walking = false;
	return depth;
}

int backtrace(const void **return_addrs, int max_depth)
{
	return backtrace_frame(__builtin_frame_address(0),
			       return_addrs, max_depth);
}
