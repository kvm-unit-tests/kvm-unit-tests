#ifndef _STACK_H_
#define _STACK_H_

#include <libcflat.h>
#include <asm/stack.h>

#ifndef HAVE_ARCH_BACKTRACE_FRAME
static inline int
backtrace_frame(const void *frame __unused, const void **return_addrs __unused,
		int max_depth __unused)
{
	return 0;
}
#endif

#ifndef HAVE_ARCH_BACKTRACE
int backtrace(const void **return_addrs, int max_depth);
#endif

#endif
