/* SPDX-License-Identifier: LGPL-2.0-only */
/*
 * Test interrupts
 *
 * Copyright 2024 Nicholas Piggin, IBM Corp.
 */
#include <libcflat.h>
#include <util.h>
#include <migrate.h>
#include <alloc.h>
#include <asm/setup.h>
#include <asm/handlers.h>
#include <asm/hcall.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/barrier.h>
#include <asm/mmu.h>
#include "alloc_phys.h"
#include "vmalloc.h"

static volatile bool got_interrupt;
static volatile struct pt_regs recorded_regs;

static void mce_handler(struct pt_regs *regs, void *opaque)
{
	bool *is_fetch = opaque;

	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	if (*is_fetch)
		regs->nip = regs->link;
	else
		regs_advance_insn(regs);
}

static void fault_handler(struct pt_regs *regs, void *opaque)
{
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	if (regs->trap == 0x400 || regs->trap == 0x480)
		regs->nip = regs->link;
	else
		regs_advance_insn(regs);
}

static void test_mce(void)
{
	unsigned long addr = -4ULL;
	uint8_t tmp;
	bool is_fetch;
	bool mmu = mmu_enabled();

	report_prefix_push("mce");

	handle_exception(0x200, mce_handler, &is_fetch);
	handle_exception(0x300, fault_handler, NULL);
	handle_exception(0x380, fault_handler, NULL);
	handle_exception(0x400, fault_handler, NULL);
	handle_exception(0x480, fault_handler, NULL);

	if (mmu)
		mmu_disable();

	if (machine_is_powernv()) {
		enable_mcheck();
	} else {
		report(mfmsr() & MSR_ME, "pseries machine has MSR[ME]=1");
		if (!(mfmsr() & MSR_ME)) { /* try to fix it */
			enable_mcheck();
		}
		if (mfmsr() & MSR_ME) {
			disable_mcheck();
			report(mfmsr() & MSR_ME, "pseries is unable to change MSR[ME]");
			if (!(mfmsr() & MSR_ME)) { /* try to fix it */
				enable_mcheck();
			}
		}
	}

	is_fetch = false;
	asm volatile("lbz %0,0(%1)" : "=r"(tmp) : "r"(addr));

	/* KVM does not MCE on access outside partition scope */
	report_kfail(host_is_kvm, got_interrupt, "MCE on access to invalid real address");
	if (got_interrupt) {
		report(mfspr(SPR_DAR) == addr, "MCE sets DAR correctly");
		if (cpu_has_power_mce)
			report(recorded_regs.msr & (1ULL << 21), "d-side MCE sets SRR1[42]");
		got_interrupt = false;
	}

	is_fetch = true;
	asm volatile("mtctr %0 ; bctrl" :: "r"(addr) : "ctr", "lr");
	/* KVM does not MCE on access outside partition scope */
	report_kfail(host_is_kvm, got_interrupt, "MCE on fetch from invalid real address");
	if (got_interrupt) {
		report(recorded_regs.nip == addr, "MCE sets SRR0 correctly");
		if (cpu_has_power_mce)
			report(!(recorded_regs.msr & (1ULL << 21)), "i-side MCE clears SRR1[42]");
		got_interrupt = false;
	}

	if (mmu)
		mmu_enable(NULL);

	handle_exception(0x200, NULL, NULL);
	handle_exception(0x300, NULL, NULL);
	handle_exception(0x380, NULL, NULL);
	handle_exception(0x400, NULL, NULL);
	handle_exception(0x480, NULL, NULL);

	report_prefix_pop();
}

static void dside_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs_advance_insn(regs);
}

static void iside_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs->nip = regs->link;
}

static void test_dseg_nommu(void)
{
	uint64_t msr, tmp;

	report_prefix_push("dseg");

	/* Some HV start in radix mode and need 0x300 */
	handle_exception(0x300, &dside_handler, NULL);
	handle_exception(0x380, &dside_handler, NULL);

	asm volatile(
"		mfmsr	%0		\n \
		ori	%1,%0,%2	\n \
		mtmsrd	%1		\n \
		lbz	%1,0(0)		\n \
		mtmsrd	%0		"
		: "=r"(msr), "=r"(tmp) : "i"(MSR_DR): "memory");

	report(got_interrupt, "interrupt on NULL dereference");
	got_interrupt = false;

	handle_exception(0x300, NULL, NULL);
	handle_exception(0x380, NULL, NULL);

	report_prefix_pop();
}

static void test_mmu(void)
{
	uint64_t tmp, addr;
	phys_addr_t base, top;

	if (!mmu_enabled()) {
		test_dseg_nommu();
		return;
	}

	phys_alloc_get_unused(&base, &top);

	report_prefix_push("dsi");
	addr = top + PAGE_SIZE;
	handle_exception(0x300, &dside_handler, NULL);
	asm volatile("lbz %0,0(%1)" : "=r"(tmp) : "r"(addr));
	report(got_interrupt, "dsi on out of range dereference");
	report(mfspr(SPR_DAR) == addr, "DAR set correctly");
	report(mfspr(SPR_DSISR) & (1ULL << 30), "DSISR set correctly");
	got_interrupt = false;
	handle_exception(0x300, NULL, NULL);
	report_prefix_pop();

	report_prefix_push("dseg");
	addr = -4ULL;
	handle_exception(0x380, &dside_handler, NULL);
	asm volatile("lbz %0,0(%1)" : "=r"(tmp) : "r"(addr));
	report(got_interrupt, "dseg on out of range dereference");
	report(mfspr(SPR_DAR) == addr, "DAR set correctly");
	got_interrupt = false;
	handle_exception(0x380, NULL, NULL);
	report_prefix_pop();

	report_prefix_push("isi");
	addr = top + PAGE_SIZE;
	handle_exception(0x400, &iside_handler, NULL);
	asm volatile("mtctr %0 ; bctrl" :: "r"(addr) : "ctr", "lr");
	report(got_interrupt, "isi on out of range fetch");
	report(recorded_regs.nip == addr, "SRR0 set correctly");
	report(recorded_regs.msr & (1ULL << 30), "SRR1 set correctly");
	got_interrupt = false;
	handle_exception(0x400, NULL, NULL);
	report_prefix_pop();

	report_prefix_push("iseg");
	addr = -4ULL;
	handle_exception(0x480, &iside_handler, NULL);
	asm volatile("mtctr %0 ; bctrl" :: "r"(addr) : "ctr", "lr");
	report(got_interrupt, "isi on out of range fetch");
	report(recorded_regs.nip == addr, "SRR0 set correctly");
	got_interrupt = false;
	handle_exception(0x480, NULL, NULL);
	report_prefix_pop();
}

static void dec_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs->msr &= ~MSR_EE;
}

static void test_dec(void)
{
	uint64_t msr;
	uint64_t tb;

	report_prefix_push("decrementer");

	handle_exception(0x900, &dec_handler, NULL);

	asm volatile(
"		mtdec	%1		\n \
		mfmsr	%0		\n \
		ori	%0,%0,%2	\n \
		mtmsrd	%0,1		"
		: "=r"(msr) : "r"(10000), "i"(MSR_EE): "memory");

	tb = get_tb();
	while (!got_interrupt) {
		if (get_tb() - tb > tb_hz * 5)
			break; /* timeout 5s */
	}

	report(got_interrupt, "interrupt on decrementer underflow");
	got_interrupt = false;

	handle_exception(0x900, NULL, NULL);

	if (!machine_is_powernv())
		goto done; /* Skip HV tests */

	handle_exception(0x980, &dec_handler, NULL);

	mtspr(SPR_LPCR, mfspr(SPR_LPCR) | LPCR_HDICE);
	asm volatile(
"		mtspr	0x136,%1	\n \
		mtdec	%3		\n \
		mfmsr	%0		\n \
		ori	%0,%0,%2	\n \
		mtmsrd	%0,1		"
		: "=r"(msr) : "r"(10000), "i"(MSR_EE), "r"(0x7fffffff): "memory");

	tb = get_tb();
	while (!got_interrupt) {
		if (get_tb() - tb > tb_hz * 5)
			break; /* timeout 5s */
	}

	mtspr(SPR_LPCR, mfspr(SPR_LPCR) & ~LPCR_HDICE);

	report(got_interrupt, "interrupt on hdecrementer underflow");
	got_interrupt = false;

	handle_exception(0x980, NULL, NULL);

done:
	report_prefix_pop();
}


static volatile uint64_t recorded_heir;

static void heai_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs_advance_insn(regs);
	if (cpu_has_heai)
		recorded_heir = mfspr(SPR_HEIR);
}

static void program_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs_advance_insn(regs);
}

/*
 * This tests invalid instruction handling. powernv (HV) should take an
 * HEAI interrupt with the HEIR SPR set to the instruction image. pseries
 * (guest) should take a program interrupt. CPUs which support prefix
 * should report prefix instruction in (H)SRR1[34].
 */
static void test_illegal(void)
{
	report_prefix_push("illegal instruction");

	if (machine_is_powernv()) {
		handle_exception(0xe40, &heai_handler, NULL);
	} else {
		handle_exception(0x700, &program_handler, NULL);
	}

	asm volatile(".long 0x12345678" ::: "memory");
	report(got_interrupt, "interrupt on invalid instruction");
	got_interrupt = false;
	if (cpu_has_heai)
		report(recorded_heir == 0x12345678, "HEIR: 0x%08lx", recorded_heir);
	report(!regs_is_prefix(&recorded_regs), "(H)SRR1 prefix bit clear");

	if (cpu_has_prefix) {
		asm volatile(".balign 8 ; .long 0x04000123; .long 0x00badc0d");
		report(got_interrupt, "interrupt on invalid prefix instruction");
		got_interrupt = false;
		if (cpu_has_heai)
			report(recorded_heir == 0x0400012300badc0d, "HEIR: 0x%08lx", recorded_heir);
		report(regs_is_prefix(&recorded_regs), "(H)SRR1 prefix bit set");
	}

	handle_exception(0xe40, NULL, NULL);
	handle_exception(0x700, NULL, NULL);

	report_prefix_pop();
}

static void dec_ignore_handler(struct pt_regs *regs, void *data)
{
	mtspr(SPR_DEC, 0x7fffffff);
}

static void test_privileged(void)
{
	unsigned long msr;

	if (!mmu_enabled())
		return;

	report_prefix_push("privileged instruction");

	handle_exception(0x700, &program_handler, NULL);
	handle_exception(0x900, &dec_ignore_handler, NULL);
	enter_usermode();
	asm volatile("mfmsr %0" : "=r"(msr) :: "memory");
	exit_usermode();
	report(got_interrupt, "interrupt on privileged instruction");
	got_interrupt = false;
	handle_exception(0x900, NULL, NULL);
	handle_exception(0x700, NULL, NULL);

	report_prefix_pop();
}

static void sc_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
}

static void test_sc(void)
{
	report_prefix_push("syscall");

	handle_exception(0xc00, &sc_handler, NULL);

	asm volatile("sc 0" ::: "memory");

	report(got_interrupt, "interrupt on sc 0 instruction");
	got_interrupt = false;
	if (cpu_has_sc_lev)
		report(((recorded_regs.msr >> 20) & 0x3) == 0, "SRR1 set LEV=0");
	if (machine_is_powernv()) {
		asm volatile("sc 1" ::: "memory");

		report(got_interrupt, "interrupt on sc 1 instruction");
		got_interrupt = false;
		if (cpu_has_sc_lev)
			report(((recorded_regs.msr >> 20) & 0x3) == 1, "SRR1 set LEV=1");
	}

	handle_exception(0xc00, NULL, NULL);

	report_prefix_pop();
}


static void trace_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs->msr &= ~(MSR_SE | MSR_BE);
}

static void program_trace_handler(struct pt_regs *regs, void *data)
{
	regs->msr &= ~(MSR_SE | MSR_BE);
	regs->nip += 4;
}

extern char trace_insn[];
extern char trace_insn2[];
extern char trace_insn3[];
extern char trace_rfid[];

static void test_trace(void)
{
	unsigned long msr;

	report_prefix_push("trace");

	handle_exception(0xd00, &trace_handler, NULL);

	msr = mfmsr() | MSR_SE;
	asm volatile(
	"	mtmsr	%0		\n"
	".global trace_insn		\n"
	"trace_insn:			\n"
	"	nop			\n"
	: : "r"(msr) : "memory");

	report(got_interrupt, "interrupt on single step");
	got_interrupt = false;
	report(recorded_regs.nip == (unsigned long)trace_insn + 4,
			"single step interrupt at the correct address");
	if (cpu_has_siar)
		report(mfspr(SPR_SIAR) == (unsigned long)trace_insn,
			"single step recorded SIAR at the correct address");

	msr = mfmsr() | MSR_SE;
	asm volatile(
	"	mtmsr	%0		\n"
	".global trace_insn2		\n"
	"trace_insn2:			\n"
	"	b	1f		\n"
	"	nop			\n"
	"1:				\n"
	: : "r"(msr) : "memory");

	report(got_interrupt, "interrupt on single step branch");
	got_interrupt = false;
	report(recorded_regs.nip == (unsigned long)trace_insn2 + 8,
			"single step interrupt at the correct address");
	if (cpu_has_siar)
		report(mfspr(SPR_SIAR) == (unsigned long)trace_insn2,
			"single step recorded SIAR at the correct address");

	msr = mfmsr() | MSR_BE;
	asm volatile(
	"	mtmsr	%0		\n"
	".global trace_insn3		\n"
	"trace_insn3:			\n"
	"	nop			\n"
	"	b	1f		\n"
	"	nop			\n"
	"1:				\n"
	: : "r"(msr) : "memory");

	report(got_interrupt, "interrupt on branch trace");
	got_interrupt = false;
	report(recorded_regs.nip == (unsigned long)trace_insn3 + 12,
			"branch trace interrupt at the correct address");
	if (cpu_has_siar)
		report(mfspr(SPR_SIAR) == (unsigned long)trace_insn3 + 4,
			"branch trace recorded SIAR at the correct address");

	handle_exception(0x700, &program_trace_handler, NULL);
	msr = mfmsr() | MSR_SE;
	asm volatile(
	"	mtmsr	%0		\n"
	"	trap			\n"
	: : "r"(msr) : "memory");

	report(!got_interrupt, "no interrupt on single step trap");
	got_interrupt = false;
	handle_exception(0x700, NULL, NULL);

	msr = mfmsr() | MSR_SE;
	mtspr(SPR_SRR0, (unsigned long)trace_rfid);
	mtspr(SPR_SRR1, mfmsr());
	asm volatile(
	"	mtmsr	%0		\n"
	"	rfid			\n"
	".global trace_rfid		\n"
	"trace_rfid:			\n"
	: : "r"(msr) : "memory");

	report(!got_interrupt, "no interrupt on single step rfid");
	got_interrupt = false;
	handle_exception(0xd00, NULL, NULL);

	report_prefix_pop();
}


int main(int argc, char **argv)
{
	report_prefix_push("interrupts");

	if (vm_available())
		setup_vm();

	if (cpu_has_power_mce)
		test_mce();
	test_mmu();
	test_illegal();
	test_privileged();
	test_dec();
	test_sc();
	test_trace();

	report_prefix_pop();

	return report_summary();
}
