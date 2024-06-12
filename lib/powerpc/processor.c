/*
 * processor control and status function
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <libcflat.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/ptrace.h>
#include <asm/setup.h>
#include <asm/barrier.h>
#include <asm/hcall.h>
#include <asm/handlers.h>
#include <asm/mmu.h>
#include <asm/smp.h>

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

	__current_cpu = (struct cpu *)mfspr(SPR_SPRG0);
	if (in_usermode())
		current_cpu()->in_user = false;

	/*
	 * We run with AIL=0, so interrupts taken with MMU disabled.
	 * Enable here.
	 */
	assert(!(mfmsr() & (MSR_IR|MSR_DR)));
	if (mmu_enabled())
		mtmsr(mfmsr() | (MSR_IR|MSR_DR));

	v = regs->trap >> 5;

	if (v < 128 && handlers[v].func) {
		handlers[v].func(regs, handlers[v].data);
		if (regs->msr & MSR_PR)
			current_cpu()->in_user = true;
		return;
	}

	printf("Unhandled CPU%d exception %#lx at NIA:0x%016lx MSR:0x%016lx\n",
		smp_processor_id(), regs->trap, regs->nip, regs->msr);
	dump_frame_stack((void *)regs->nip, (void *)regs->gpr[1]);
	abort();
}

uint64_t get_clock_us(void)
{
	return get_tb() * 1000000 / tb_hz;
}

uint64_t get_clock_ms(void)
{
	return get_tb() * 1000 / tb_hz;
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

	if (!machine_is_pseries()) {
		/*
		 * P9/10 Could use 'stop' to sleep here which would be
		 * interesting.  stop with ESL=0 should be simple enough, ESL=1
		 * would require SRESET based wakeup which is more involved.
		 */
		delay(cycles);
		return;
	}

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

static void rfid_msr(uint64_t msr)
{
	uint64_t tmp;

	asm volatile(
		"mtsrr1	%1		\n\
		 bl	0f		\n\
		 0:			\n\
		 mflr	%0		\n\
		 addi	%0,%0,1f-0b	\n\
		 mtsrr0	%0		\n\
		 rfid			\n\
		 1:			\n"
		: "=r"(tmp) : "r"(msr) : "lr");
}

void enable_mcheck(void)
{
	/* This is a no-op on pseries */
	rfid_msr(mfmsr() | MSR_ME);
}

void disable_mcheck(void)
{
	rfid_msr(mfmsr() & ~MSR_ME);
}

bool in_usermode(void)
{
	return current_cpu()->in_user;
}

static void usermode_sc_handler(struct pt_regs *regs, void *data)
{
	regs->msr &= ~(MSR_PR|MSR_EE);
	/* Interrupt return handler will keep in_user clear */
}

void enter_usermode(void)
{
	assert_msg(!in_usermode(), "enter_usermode called with in_usermode");
	/* mfmsr would fault in usermode anyway */
	assert_msg(!(mfmsr() & MSR_PR), "enter_usermode called from user mode");
	assert_msg(!(mfmsr() & MSR_EE), "enter_usermode called with interrupts enabled");
	assert_msg((mfmsr() & (MSR_IR|MSR_DR)) == (MSR_IR|MSR_DR),
		"enter_usermode called with virtual memory disabled");

	handle_exception(0xc00, usermode_sc_handler, NULL);
	rfid_msr(mfmsr() | (MSR_PR|MSR_IR|MSR_DR|MSR_EE));
	current_cpu()->in_user = true;
}

void exit_usermode(void)
{
	assert_msg(in_usermode(), "enter_usermode called with !in_usermode");
	asm volatile("sc 0" ::: "memory");
	handle_exception(0xc00, NULL, NULL);
	assert(!in_usermode());
	assert(!(mfmsr() & MSR_PR));
}
