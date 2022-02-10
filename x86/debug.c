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
#include <asm/debugreg.h>

#include "libcflat.h"
#include "processor.h"
#include "desc.h"
#include "usermode.h"

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
		regs->rflags |= X86_EFLAGS_RF;

	if (++n >= 10) {
		regs->rflags &= ~X86_EFLAGS_TF;
		write_dr7(0x00000400);
	}
}

static inline bool is_single_step_db(unsigned long dr6_val)
{
	return dr6_val == (DR6_ACTIVE_LOW | DR6_BS);
}

static inline bool is_general_detect_db(unsigned long dr6_val)
{
	return dr6_val == (DR6_ACTIVE_LOW | DR6_BD);
}

static inline bool is_icebp_db(unsigned long dr6_val)
{
	return dr6_val == DR6_ACTIVE_LOW;
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

typedef unsigned long (*db_test_fn)(void);
typedef void (*db_report_fn)(unsigned long, const char *);

static unsigned long singlestep_with_movss_blocking_and_dr7_gd(void);

static void __run_single_step_db_test(db_test_fn test, db_report_fn report_fn)
{
	unsigned long start;
	bool ign;

	n = 0;
	write_dr6(0);

	start = test();
	report_fn(start, "");

	/* MOV DR #GPs at CPL>0, don't try to run the DR7.GD test in usermode. */
	if (test == singlestep_with_movss_blocking_and_dr7_gd)
		return;

	n = 0;
	write_dr6(0);

	/*
	 * Run the test in usermode.  Use the expected start RIP from the first
	 * run, the usermode framework doesn't make it easy to get the expected
	 * RIP out of the test, and it shouldn't change in any case.  Run the
	 * test with IOPL=3 so that it can use OUT, CLI, STI, etc...
	 */
	set_iopl(3);
	run_in_user((usermode_func)test, GP_VECTOR, 0, 0, 0, 0, &ign);
	set_iopl(0);

	report_fn(start, "Usermode ");
}

#define run_ss_db_test(name) __run_single_step_db_test(name, report_##name)

static void report_singlestep_basic(unsigned long start, const char *usermode)
{
	report(n == 3 &&
	       is_single_step_db(dr6[0]) && db_addr[0] == start &&
	       is_single_step_db(dr6[1]) && db_addr[1] == start + 1 &&
	       is_single_step_db(dr6[2]) && db_addr[2] == start + 1 + 1,
	       "%sSingle-step #DB basic test", usermode);
}

static unsigned long singlestep_basic(void)
{
	unsigned long start;

	/*
	 * After being enabled, single-step breakpoints have a one instruction
	 * delay before the first #DB is generated.
	 */
	asm volatile (
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		"and $~(1<<8),%%rax\n\t"
		"1:push %%rax\n\t"
		"popf\n\t"
		"lea 1b(%%rip), %0\n\t"
		: "=r" (start) : : "rax"
	);
	return start;
}

static void report_singlestep_emulated_instructions(unsigned long start,
						    const char *usermode)
{
	report(n == 7 &&
	       is_single_step_db(dr6[0]) && db_addr[0] == start &&
	       is_single_step_db(dr6[1]) && db_addr[1] == start + 1 &&
	       is_single_step_db(dr6[2]) && db_addr[2] == start + 1 + 3 &&
	       is_single_step_db(dr6[3]) && db_addr[3] == start + 1 + 3 + 2 &&
	       is_single_step_db(dr6[4]) && db_addr[4] == start + 1 + 3 + 2 + 5 &&
	       is_single_step_db(dr6[5]) && db_addr[5] == start + 1 + 3 + 2 + 5 + 1 &&
	       is_single_step_db(dr6[6]) && db_addr[6] == start + 1 + 3 + 2 + 5 + 1 + 1,
	       "%sSingle-step #DB on emulated instructions", usermode);
}

static unsigned long singlestep_emulated_instructions(void)
{
	unsigned long start;

	/*
	 * Verify single-step #DB are generated correctly on emulated
	 * instructions, e.g. CPUID and RDMSR.
	 */
	asm volatile (
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		"and $~(1<<8),%%rax\n\t"
		"1:push %%rax\n\t"
		"xor %%rax,%%rax\n\t"
		"cpuid\n\t"
		"movl $0x3fd, %%edx\n\t"
		"inb %%dx, %%al\n\t"
		"popf\n\t"
		"lea 1b(%%rip),%0\n\t"
		: "=r" (start) : : "rax", "ebx", "ecx", "edx"
	);
	return start;
}

static void report_singlestep_with_sti_blocking(unsigned long start,
						const char *usermode)
{
	report(n == 4 &&
	       is_single_step_db(dr6[0]) && db_addr[0] == start &&
	       is_single_step_db(dr6[1]) && db_addr[1] == start + 6 &&
	       is_single_step_db(dr6[2]) && db_addr[2] == start + 6 + 1 &&
	       is_single_step_db(dr6[3]) && db_addr[3] == start + 6 + 1 + 1,
	       "%sSingle-step #DB w/ STI blocking", usermode);
}


static unsigned long singlestep_with_sti_blocking(void)
{
	unsigned long start_rip;

	/*
	 * STI blocking doesn't suppress #DBs, thus the first single-step #DB
	 * should arrive after the standard one instruction delay.
	 */
	asm volatile(
		"cli\n\t"
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		"sti\n\t"
		"1:and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		"lea 1b(%%rip),%0\n\t"
		: "=r" (start_rip) : : "rax"
	);
	return start_rip;
}

static void report_singlestep_with_movss_blocking(unsigned long start,
						  const char *usermode)
{
	report(n == 3 &&
	       is_single_step_db(dr6[0]) && db_addr[0] == start &&
	       is_single_step_db(dr6[1]) && db_addr[1] == start + 1 &&
	       is_single_step_db(dr6[2]) && db_addr[2] == start + 1 + 1,
	       "%sSingle-step #DB w/ MOVSS blocking", usermode);
}

static unsigned long singlestep_with_movss_blocking(void)
{
	unsigned long start_rip;

	/*
	 * MOVSS blocking suppresses single-step #DBs (and select other #DBs),
	 * thus the first single-step #DB should occur after MOVSS blocking
	 * expires, i.e. two instructions after #DBs are enabled in this case.
	 */ 
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"mov %%ss, %%ax\n\t"
		"popf\n\t"
		"mov %%ax, %%ss\n\t"
		"and $~(1<<8),%%rax\n\t"
		"1: push %%rax\n\t"
		"popf\n\t"
		"lea 1b(%%rip),%0\n\t"
		: "=r" (start_rip) : : "rax"
	);
	return start_rip;
}


static void report_singlestep_with_movss_blocking_and_icebp(unsigned long start,
							    const char *usermode)
{
	report(n == 4 &&
	       is_icebp_db(dr6[0]) && db_addr[0] == start &&
	       is_single_step_db(dr6[1]) && db_addr[1] == start + 6 &&
	       is_single_step_db(dr6[2]) && db_addr[2] == start + 6 + 1 &&
	       is_single_step_db(dr6[3]) && db_addr[3] == start + 6 + 1 + 1,
	       "%sSingle-Step + ICEBP #DB w/ MOVSS blocking", usermode);
}

static unsigned long singlestep_with_movss_blocking_and_icebp(void)
{
	unsigned long start;

	/*
	 * ICEBP, a.k.a. INT1 or int1icebrk, is an oddball.  It generates a
	 * trap-like #DB, is intercepted if #DBs are intercepted, and manifests
	 * as a #DB VM-Exit, but the VM-Exit occurs on the ICEBP itself, i.e.
	 * it's treated as an instruction intercept.  Verify that ICEBP is
	 * correctly emulated as a trap-like #DB when intercepted, and that
	 * MOVSS blocking is handled correctly with respect to single-step
	 * breakpoints being enabled.
	 */
	asm volatile(
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"mov %%ss, %%ax\n\t"
		"popf\n\t"
		"mov %%ax, %%ss\n\t"
		".byte 0xf1;"
		"1:and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		"lea 1b(%%rip),%0\n\t"
		: "=r" (start) : : "rax"
	);
	return start;
}

static void report_singlestep_with_movss_blocking_and_dr7_gd(unsigned long start,
							     const char *ign)
{
	report(n == 5 &&
	       is_general_detect_db(dr6[0]) && db_addr[0] == start &&
	       is_single_step_db(dr6[1]) && db_addr[1] == start + 3 &&
	       is_single_step_db(dr6[2]) && db_addr[2] == start + 3 + 6 &&
	       is_single_step_db(dr6[3]) && db_addr[3] == start + 3 + 6 + 1 &&
	       is_single_step_db(dr6[4]) && db_addr[4] == start + 3 + 6 + 1 + 1,
	       "Single-step #DB w/ MOVSS blocking and DR7.GD=1");
}

static unsigned long singlestep_with_movss_blocking_and_dr7_gd(void)
{
	unsigned long start_rip;

	write_dr7(DR7_GD);

	/*
	 * MOVSS blocking does NOT suppress General Detect #DBs, which have
	 * fault-like behavior.  Note, DR7.GD is cleared by the CPU upon
	 * successful delivery of the #DB.  DR6.BD is NOT cleared by the CPU,
	 * but the MOV DR6 below will be re-executed after handling the
	 * General Detect #DB.
	 */
	asm volatile(
		"xor %0, %0\n\t"
		"pushf\n\t"
		"pop %%rax\n\t"
		"or $(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"mov %%ss, %%ax\n\t"
		"popf\n\t"
		"mov %%ax, %%ss\n\t"
		"1: mov %0, %%dr6\n\t"
		"and $~(1<<8),%%rax\n\t"
		"push %%rax\n\t"
		"popf\n\t"
		"lea 1b(%%rip),%0\n\t"
		: "=r" (start_rip) : : "rax"
	);
	return start_rip;
}

int main(int ac, char **av)
{
	unsigned long cr4;

	handle_exception(DB_VECTOR, handle_db);
	handle_exception(BP_VECTOR, handle_bp);
	handle_exception(UD_VECTOR, handle_ud);

	/*
	 * DR4 is an alias for DR6 (and DR5 aliases DR7) if CR4.DE is NOT set,
	 * and is reserved if CR4.DE=1 (Debug Extensions enabled).
	 */
	got_ud = 0;
	cr4 = read_cr4();
	write_cr4(cr4 & ~X86_CR4_DE);
	write_dr4(0);
	write_dr6(DR6_ACTIVE_LOW | DR6_BS | DR6_TRAP1);
	report(read_dr4() == (DR6_ACTIVE_LOW | DR6_BS | DR6_TRAP1) && !got_ud,
	       "DR4==DR6 with CR4.DE == 0");

	cr4 = read_cr4();
	write_cr4(cr4 | X86_CR4_DE);
	read_dr4();
	report(got_ud, "DR4 read got #UD with CR4.DE == 1");
	write_dr6(0);

	extern unsigned char sw_bp;
	asm volatile("int3; sw_bp:");
	report(bp_addr == (unsigned long)&sw_bp, "#BP");

	/*
	 * The CPU sets/clears bits 0-3 (trap bits for DR0-3) on #DB based on
	 * whether or not the corresponding DR0-3 got a match.  All other bits
	 * in DR6 are set if and only if their associated breakpoint condition
	 * is active, and are never cleared by the CPU.  Verify a match on DR0
	 * is reported correctly, and that DR6.BS is not set when single-step
	 * breakpoints are disabled, but is left set (if set by software).
	 */
	n = 0;
	extern unsigned char hw_bp1;
	write_dr0(&hw_bp1);
	write_dr7(DR7_FIXED_1 | DR7_GLOBAL_ENABLE_DR0);
	asm volatile("hw_bp1: nop");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_bp1) &&
	       dr6[0] == (DR6_ACTIVE_LOW | DR6_TRAP0),
	       "hw breakpoint (test that dr6.BS is not set)");

	n = 0;
	extern unsigned char hw_bp2;
	write_dr0(&hw_bp2);
	write_dr6(DR6_BS | DR6_TRAP1);
	asm volatile("hw_bp2: nop");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_bp2) &&
	       dr6[0] == (DR6_ACTIVE_LOW | DR6_BS | DR6_TRAP0),
	       "hw breakpoint (test that dr6.BS is not cleared)");

	run_ss_db_test(singlestep_basic);
	run_ss_db_test(singlestep_emulated_instructions);
	run_ss_db_test(singlestep_with_sti_blocking);
	run_ss_db_test(singlestep_with_movss_blocking);
	run_ss_db_test(singlestep_with_movss_blocking_and_icebp);
	run_ss_db_test(singlestep_with_movss_blocking_and_dr7_gd);

	n = 0;
	write_dr1((void *)&value);
	write_dr6(DR6_BS);
	write_dr7(0x00d0040a); // 4-byte write

	extern unsigned char hw_wp1;
	asm volatile(
		"mov $42,%%rax\n\t"
		"mov %%rax,%0\n\t; hw_wp1:"
		: "=m" (value) : : "rax");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_wp1) &&
	       dr6[0] == (DR6_ACTIVE_LOW | DR6_BS | DR6_TRAP1),
	       "hw watchpoint (test that dr6.BS is not cleared)");

	n = 0;
	write_dr6(0);

	extern unsigned char hw_wp2;
	asm volatile(
		"mov $42,%%rax\n\t"
		"mov %%rax,%0\n\t; hw_wp2:"
		: "=m" (value) : : "rax");
	report(n == 1 &&
	       db_addr[0] == ((unsigned long)&hw_wp2) &&
	       dr6[0] == (DR6_ACTIVE_LOW | DR6_TRAP1),
	       "hw watchpoint (test that dr6.BS is not set)");

	n = 0;
	write_dr6(0);
	extern unsigned char sw_icebp;
	asm volatile(".byte 0xf1; sw_icebp:");
	report(n == 1 &&
	       db_addr[0] == (unsigned long)&sw_icebp && dr6[0] == DR6_ACTIVE_LOW,
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
