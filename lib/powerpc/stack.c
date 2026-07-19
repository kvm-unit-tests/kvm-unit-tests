#include <libcflat.h>
#include <asm/ptrace.h>
#include <stack.h>

extern char do_handle_exception_return[];

int arch_backtrace_frame(const void *frame, const void **return_addrs,
			 int max_depth, bool current_frame)
{
	static int walking;
	int depth = 0;
	const unsigned long *bp = (unsigned long *)frame;
	void *return_addr;

	asm volatile("" ::: "lr"); /* Force it to save LR */

	if (walking) {
		printf("RECURSIVE STACK WALK!!!\n");
		return 0;
	}
	walking = 1;

	if (current_frame)
		bp = __builtin_frame_address(0);

	bp = (unsigned long *)bp[0];
	return_addr = (void *)bp[2];

	for (depth = 0; bp && depth < max_depth; depth++) {
		return_addrs[depth] = return_addr;
		if (return_addrs[depth] == 0)
			break;
		if (return_addrs[depth] == do_handle_exception_return) {
			struct pt_regs *regs;

			regs = (void *)bp + STACK_FRAME_OVERHEAD;
			bp = (unsigned long *)bp[0];
			/* Represent interrupt frame with vector number */
			return_addr = (void *)regs->trap;
			if (depth + 1 < max_depth) {
				depth++;
				return_addrs[depth] = return_addr;
				return_addr = (void *)regs->nip;
			}
		} else {
			bp = (unsigned long *)bp[0];
			return_addr = (void *)bp[2];
		}
	}

	walking = 0;
	return depth;
}
