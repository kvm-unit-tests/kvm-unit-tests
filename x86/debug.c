/*
 * Test for x86 debugging facilities
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "libcflat.h"
#include "processor.h"
#include "desc.h"

static volatile unsigned long bp_addr;
static volatile unsigned long db_addr[10], dr6[10];
static volatile unsigned int n;
static volatile unsigned long value;

static inline void write_dr4(ulong val)
{
    asm volatile ("mov %0, %%dr4" : : "r"(val) : "memory");
}

static inline ulong read_dr4(void)
{
    ulong val;
    asm volatile ("mov %%dr4, %0" : "=r"(val));
    return val;
}

static void handle_db(struct ex_regs *regs)
{
	db_addr[n] = regs->rip;
	dr6[n] = read_dr6();

	if (dr6[n] & 0x1)
		regs->rflags |= (1 << 16);

	if (++n >= 10) {
		regs->rflags &= ~(1 << 8);
		write_dr7(0x00000400);
	}
}

extern unsigned char handle_db_save_rip;
asm("handle_db_save_rip:\n"
   "stc\n"
   "nop;nop;nop\n"
   "rclq $1, n(%rip)\n"
   "iretq\n");

static void handle_bp(struct ex_regs *regs)
{
	bp_addr = regs->rip;
}

bool got_ud;
static void handle_ud(struct ex_regs *regs)
{
	unsigned long cr4 = read_cr4();
	write_cr4(cr4 & ~X86_CR4_DE);
	got_ud = 1;
}

int main(int ac, char **av)
{
	unsigned long start;
	unsigned long cr4;

	handle_exception(DB_VECTOR, handle_db);
	handle_exception(BP_VECTOR, handle_bp);
	handle_exception(UD_VECTOR, handle_ud);

	got_ud = 0;
	cr4 = read_cr4();
	write_cr4(cr4 & ~X86_CR4_DE);
	write_dr4(0);
	write_dr6(0xffff4ff2);
	report(read_dr4() == 0xffff4ff2 && !got_ud, "reading DR4 with CR4.DE == 0");

	cr4 = read_cr4();
	write_cr4(cr4 | X86_CR4_DE);
	read_dr4();
	report(got_ud, "reading DR4 with CR4.DE == 1");
	write_dr6(0);

	extern unsigned char sw_bp;
	asm volatile("int3; sw_bp:");
	report(bp_addr == (unsigned long)&sw_bp, "#BP");

	n = 0;
	extern unsigned char hw_bp1;
	write_dr0(&hw_bp1);
	write_dr7(0x00000402);
	asm volatile("hw_bp1: nop");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_bp1) && dr6[0] == 0xffff0ff1,
	       "hw breakpoint (test that dr6.BS is not set)");

	n = 0;
	extern unsigned char hw_bp2;
	write_dr0(&hw_bp2);
	write_dr6(0x00004002);
	asm volatile("hw_bp2: nop");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_bp2) && dr6[0] == 0xffff4ff1,
	       "hw breakpoint (test that dr6.BS is not cleared)");

	n = 0;
	write_dr6(0);
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"lea (%%rip),%0\n\t"
		"popf\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		: "=r" (start) : : "rax");
	report(n == 3 &&
	       db_addr[0] == start + 1 + 6 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == start + 1 + 6 + 1 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == start + 1 + 6 + 1 + 1 && dr6[2] == 0xffff4ff0,
	       "single step");

	/*
	 * cpuid and rdmsr (among others) trigger VM exits and are then
	 * emulated. Test that single stepping works on emulated instructions.
	 */
	n = 0;
	write_dr6(0);
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"lea (%%rip),%0\n\t"
		"popf\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"xor %%rax,%%rax\n\t"
		"cpuid\n\t"
		"movl $0x1a0,%%ecx\n\t"
		"rdmsr\n\t"
		"popf\n\t"
		: "=r" (start) : : "rax", "ebx", "ecx", "edx");
	report(n == 7 &&
	       db_addr[0] == start + 1 + 6 && dr6[0] == 0xffff4ff0 &&
	       db_addr[1] == start + 1 + 6 + 1 && dr6[1] == 0xffff4ff0 &&
	       db_addr[2] == start + 1 + 6 + 1 + 3 && dr6[2] == 0xffff4ff0 &&
	       db_addr[3] == start + 1 + 6 + 1 + 3 + 2 && dr6[3] == 0xffff4ff0 &&
	       db_addr[4] == start + 1 + 6 + 1 + 3 + 2 + 5 && dr6[4] == 0xffff4ff0 &&
	       db_addr[5] == start + 1 + 6 + 1 + 3 + 2 + 5 + 2 && dr6[5] == 0xffff4ff0 &&
	       db_addr[6] == start + 1 + 6 + 1 + 3 + 2 + 5 + 2 + 1 && dr6[6] == 0xffff4ff0,
	       "single step emulated instructions");

	n = 0;
	write_dr1((void *)&value);
	write_dr7(0x00d0040a); // 4-byte write

	extern unsigned char hw_wp1;
	asm volatile(
		"mov $42,%%rax\n\t"
		"mov %%rax,%0\n\t; hw_wp1:"
		: "=m" (value) : : "rax");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_wp1) && dr6[0] == 0xffff4ff2,
	       "hw watchpoint (test that dr6.BS is not cleared)");

	n = 0;
	write_dr6(0);

	extern unsigned char hw_wp2;
	asm volatile(
		"mov $42,%%rax\n\t"
		"mov %%rax,%0\n\t; hw_wp2:"
		: "=m" (value) : : "rax");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_wp2) && dr6[0] == 0xffff0ff2,
	       "hw watchpoint (test that dr6.BS is not set)");

	n = 0;
	write_dr6(0);
	extern unsigned char sw_icebp;
	asm volatile(".byte 0xf1; sw_icebp:");
	report(n == 1 &&
	       db_addr[0] == (unsigned long)&sw_icebp && dr6[0] == 0xffff0ff0,
	       "icebp");

	write_dr7(0x400);
	value = KERNEL_DS;
	write_dr7(0x00f0040a); // 4-byte read or write

	/*
	 * Each invocation of the handler should shift n by 1 and set bit 0 to 1.
	 * We expect a single invocation, so n should become 3.  If the entry
	 * RIP is wrong, or if the handler is executed more than once, the value
	 * will not match.
	 */
	set_idt_entry(1, &handle_db_save_rip, 0);

	n = 1;
	asm volatile(
		"clc\n\t"
		"mov %0,%%ss\n\t"
		".byte 0x2e, 0x2e, 0xf1"
		: "=m" (value) : : "rax");
	report(n == 3, "MOV SS + watchpoint + ICEBP");

	/*
	 * Here the #DB handler is invoked twice, once as a software exception
	 * and once as a software interrupt.
	 */
	n = 1;
	asm volatile(
		"clc\n\t"
		"mov %0,%%ss\n\t"
		"int $1"
		: "=m" (value) : : "rax");
	report(n == 7, "MOV SS + watchpoint + int $1");

	/*
	 * Here the #DB and #BP handlers are invoked once each.
	 */
	n = 1;
	bp_addr = 0;
	asm volatile(
		"mov %0,%%ss\n\t"
		".byte 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0xcc\n\t"
		"sw_bp2:"
		: "=m" (value) : : "rax");
	extern unsigned char sw_bp2;
	report(n == 3 && bp_addr == (unsigned long)&sw_bp2,
	       "MOV SS + watchpoint + INT3");
	return report_summary();
}
