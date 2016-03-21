/*
 * processor control and status function
 */

#include <libcflat.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

static struct {
	void (*func)(struct pt_regs *, void *data);
	void *data;
} handlers[16];

void handle_exception(int trap, void (*func)(struct pt_regs *, void *),
		      void * data)
{
	trap >>= 8;

	if (trap < 16) {
		handlers[trap].func = func;
		handlers[trap].data = data;
	}
}

void do_handle_exception(struct pt_regs *regs)
{
	unsigned char v;

	v = regs->trap >> 8;

	if (v < 16 && handlers[v].func) {
		handlers[v].func(regs, handlers[v].data);
		return;
	}

	printf("unhandled cpu exception 0x%lx\n", regs->trap);
	abort();
}
