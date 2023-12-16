/*
 * processor control and status function
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <libcflat.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/setup.h>
#include <asm/barrier.h>
#include <asm/hcall.h>
#include <asm/handlers.h>

static struct {
	void (*func)(struct pt_regs *, void *data);
	void *data;
} handlers[128];

/*
 * Exception handlers span from 0x100 to 0x1000 and can have a granularity
 * of 0x20 bytes in some cases. Indexing spans 0-0x1000 with 0x20 increments
 * resulting in 128 slots.
 */
void handle_exception(int trap, void (*func)(struct pt_regs *, void *),
		      void * data)
{
	assert(!(trap & ~0xfe0));

	trap >>= 5;

	if (func && handlers[trap].func) {
		printf("exception handler installed twice %#x\n", trap << 5);
		abort();
	}

	handlers[trap].func = func;
	handlers[trap].data = data;
}

void do_handle_exception(struct pt_regs *regs)
{
	unsigned char v;

	v = regs->trap >> 5;

	if (v < 128 && handlers[v].func) {
		handlers[v].func(regs, handlers[v].data);
		return;
	}

	printf("unhandled cpu exception %#lx at NIA:0x%016lx MSR:0x%016lx\n", regs->trap, regs->nip, regs->msr);
	abort();
}

void delay(uint64_t cycles)
{
	uint64_t start = get_tb();

	while ((get_tb() - start) < cycles)
		cpu_relax();
}

void udelay(uint64_t us)
{
	delay((us * tb_hz) / 1000000);
}

void sleep_tb(uint64_t cycles)
{
	uint64_t start, end, now;

	start = now = get_tb();
	end = start + cycles;

	while (end > now) {
		uint64_t left = end - now;

		/* TODO: Could support large decrementer */
		if (left > 0x7fffffff)
			left = 0x7fffffff;

		/* DEC won't fire until H_CEDE is called because EE=0 */
		asm volatile ("mtdec %0" : : "r" (left));
		handle_exception(0x900, &dec_handler_oneshot, NULL);
		/*
		 * H_CEDE is called with MSR[EE] clear and enables it as part
		 * of the hcall, returning with EE enabled. The dec interrupt
		 * is then taken immediately and the handler disables EE.
		 *
		 * If H_CEDE returned for any other interrupt than dec
		 * expiring, that is considered an unhandled interrupt and
		 * the test case would be stopped.
		 */
		if (hcall(H_CEDE) != H_SUCCESS) {
			printf("H_CEDE failed\n");
			abort();
		}
		handle_exception(0x900, NULL, NULL);

		now = get_tb();
	}
}

void usleep(uint64_t us)
{
	sleep_tb((us * tb_hz) / 1000000);
}
