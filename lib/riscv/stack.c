// SPDX-License-Identifier: GPL-2.0-only
#include <libcflat.h>
#include <stack.h>

#ifdef CONFIG_RELOC
extern char ImageBase, _text, _etext;

bool base_address(const void *rebased_addr, unsigned long *addr)
{
	unsigned long ra = (unsigned long)rebased_addr;
	unsigned long base = (unsigned long)&ImageBase;
	unsigned long start = (unsigned long)&_text;
	unsigned long end = (unsigned long)&_etext;

	if (ra < start || ra >= end)
		return false;

	*addr = ra - base;
	return true;
}
#endif

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
