// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test PMU
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
#include <asm/smp.h>
#include "alloc_phys.h"
#include "vmalloc.h"

static volatile bool got_interrupt;
static volatile struct pt_regs recorded_regs;
static volatile unsigned long recorded_mmcr0;

static void illegal_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	regs_advance_insn(regs);
}

static void fault_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	regs_advance_insn(regs);
}

static void sc_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
}

static void reset_mmcr0(void)
{
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_PMAE | MMCR0_PMAO));
}

static __attribute__((__noinline__)) unsigned long pmc5_count_nr_insns(unsigned long nr)
{
	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile("mtctr %0 ; 1: bdnz 1b" :: "r"(nr) : "ctr");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));

	return mfspr(SPR_PMC5);
}

static void test_pmc5(void)
{
	unsigned long pmc5;
	unsigned long mmcr;

	reset_mmcr0();
	mmcr = mfspr(SPR_MMCR0);
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mmcr & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 20 ; nop ; .endr" ::: "memory");
	mtspr(SPR_MMCR0, mmcr);
	pmc5 = mfspr(SPR_PMC5);

	report_kfail(true, pmc5 == 21, "PMC5 counts instructions exactly %ld", pmc5);
}

static void test_pmc5_with_branch(void)
{
	unsigned long pmc5;
	unsigned long mmcr;

	reset_mmcr0();
	mmcr = mfspr(SPR_MMCR0);
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mmcr & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 20 ; b $+4 ; .endr" ::: "memory");
	mtspr(SPR_MMCR0, mmcr);
	pmc5 = mfspr(SPR_PMC5);

	/* TCG and POWER9 do not count instructions around faults correctly */
	report_kfail(true, pmc5 == 21, "PMC5 counts instructions with branch %ld", pmc5);
}

static void test_pmc5_with_cond_branch(void)
{
	unsigned long pmc5;
	unsigned long mmcr;

	reset_mmcr0();
	mmcr = mfspr(SPR_MMCR0);
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mmcr & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 10 ; nop ; .endr ; cmpdi %0,1 ; beq 1f ; .rep 10 ; nop ; .endr ; 1:" :  : "r"(0) : "memory", "cr0");
	mtspr(SPR_MMCR0, mmcr);
	pmc5 = mfspr(SPR_PMC5);

	/* TCG and POWER9 do not count instructions around faults correctly */
	report_kfail(true, pmc5 == 24,
		     "PMC5 counts instructions wth conditional branch %ld", pmc5);
}

static void test_pmc5_with_ill(void)
{
	unsigned long pmc5_1, pmc5_2;

	handle_exception(0x700, &illegal_handler, NULL);
	handle_exception(0xe40, &illegal_handler, NULL);

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".long 0x0" ::: "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	assert(got_interrupt);
	got_interrupt = false;
	pmc5_1 = mfspr(SPR_PMC5);

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 10 ; nop ; .endr ; .long 0x0 ; .rep 10 ; nop ; .endr " ::: "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	assert(got_interrupt);
	got_interrupt = false;
	pmc5_2 = mfspr(SPR_PMC5);

	/* TCG and POWER9 do not count instructions around faults correctly */
	report_kfail(true, pmc5_1 + 20 == pmc5_2,
		     "PMC5 counts instructions with illegal instruction");

	handle_exception(0x700, NULL, NULL);
	handle_exception(0xe40, NULL, NULL);
}

static void test_pmc5_with_fault(void)
{
	unsigned long pmc5_1, pmc5_2;
	unsigned long tmp;

	setup_vm();

	handle_exception(0x300, &fault_handler, NULL);
	handle_exception(0x380, &fault_handler, NULL);

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile("ld %0,0(%1)" : "=r"(tmp) : "r"(NULL) : "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	assert(got_interrupt);
	got_interrupt = false;
	pmc5_1 = mfspr(SPR_PMC5);

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 10 ; nop ; .endr ; ld %0,0(%1) ; .rep 10 ; nop ; .endr " : "=r"(tmp) : "r"(NULL) : "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	assert(got_interrupt);
	got_interrupt = false;
	pmc5_2 = mfspr(SPR_PMC5);

	/* TCG and POWER9 do not count instructions around faults correctly */
	report_kfail(true, pmc5_1 + 20 == pmc5_2, "PMC5 counts instructions with fault");

	handle_exception(0x300, NULL, NULL);
	handle_exception(0x380, NULL, NULL);
}

static void test_pmc5_with_sc(void)
{
	unsigned long pmc5_1, pmc5_2;

	handle_exception(0xc00, &sc_handler, NULL);

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile("sc 0" ::: "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	assert(got_interrupt);
	got_interrupt = false;
	pmc5_1 = mfspr(SPR_PMC5);

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 10 ; nop ; .endr ; sc 0 ; .rep 10 ; nop ; .endr" ::: "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	assert(got_interrupt);
	got_interrupt = false;
	pmc5_2 = mfspr(SPR_PMC5);

	/* TCG does not count instructions around syscalls correctly */
	report_kfail(host_is_tcg, pmc5_1 + 20 == pmc5_2,
		     "PMC5 counts instructions with syscall");

	handle_exception(0xc00, NULL, NULL);
}

extern char next_insn[];

static void test_pmc5_with_rfid(void)
{
	unsigned long pmc5;
	unsigned long mmcr;

	mtspr(SPR_SRR0, (unsigned long)next_insn);
	mtspr(SPR_SRR1, mfmsr());
	reset_mmcr0();
	mmcr = mfspr(SPR_MMCR0);
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mmcr & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile("rfid ; trap ; .global next_insn ; next_insn: " ::: "memory");
	mtspr(SPR_MMCR0, mmcr);
	pmc5 = mfspr(SPR_PMC5);

	/* TCG does not count instructions around syscalls correctly */
	report_kfail(host_is_tcg, pmc5 == 2,
		     "PMC5 counts instructions with rfid %ld", pmc5);
}

static void test_pmc5_with_ldat(void)
{
	unsigned long pmc5_1, pmc5_2;
	register unsigned long r4 asm("r4");
	register unsigned long r5 asm("r5");
	register unsigned long r6 asm("r6");
	uint64_t val;

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 20 ; nop ; .endr" ::: "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	pmc5_1 = mfspr(SPR_PMC5);

	val = 0xdeadbeef;
	r4 = 0;
	r5 = 0xdeadbeef;
	r6 = 100;
	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FC56));
	asm volatile(".rep 10 ; nop ; .endr ; "
		     "ldat %0,%3,0x10 ; "
		     ".rep 10 ; nop ; .endr"
		     : "=r"(r4), "+r"(r5), "+r"(r6)
		     : "r"(&val)
		     : "memory");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	pmc5_2 = mfspr(SPR_PMC5);
	assert(r4 == 0xdeadbeef);
	assert(val == 0xdeadbeef);

	/* TCG does not count instructions around syscalls correctly */
	report_kfail(host_is_tcg, pmc5_1 != pmc5_2 + 1,
		     "PMC5 counts instructions with ldat");
}

static void test_pmc56(void)
{
	unsigned long tmp;

	report_prefix_push("pmc56");

	reset_mmcr0();
	mtspr(SPR_PMC5, 0);
	mtspr(SPR_PMC6, 0);
	report(mfspr(SPR_PMC5) == 0, "PMC5 zeroed");
	report(mfspr(SPR_PMC6) == 0, "PMC6 zeroed");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~MMCR0_FC);
	msleep(100);
	report(mfspr(SPR_PMC5) == 0, "PMC5 frozen");
	report(mfspr(SPR_PMC6) == 0, "PMC6 frozen");
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~MMCR0_FC56);
	mdelay(100);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | (MMCR0_FC | MMCR0_FC56));
	report(mfspr(SPR_PMC5) != 0, "PMC5 counting");
	report(mfspr(SPR_PMC6) != 0, "PMC6 counting");

	/* Dynamic frequency scaling could cause to be out, so don't fail. */
	tmp = mfspr(SPR_PMC6);
	report(true, "PMC6 ratio to reported clock frequency is %ld%%",
	       tmp * 1000 / cpu_hz);

	tmp = pmc5_count_nr_insns(100);
	tmp = pmc5_count_nr_insns(1000) - tmp;
	report(tmp == 900, "PMC5 counts instructions precisely %ld", tmp);

	test_pmc5();
	test_pmc5_with_branch();
	test_pmc5_with_cond_branch();
	test_pmc5_with_ill();
	test_pmc5_with_fault();
	test_pmc5_with_sc();
	test_pmc5_with_rfid();
	test_pmc5_with_ldat();

	report_prefix_pop();
}

static void dec_ignore_handler(struct pt_regs *regs, void *data)
{
	mtspr(SPR_DEC, 0x7fffffff);
}

static void pmi_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	recorded_mmcr0 = mfspr(SPR_MMCR0);
	if (mfspr(SPR_MMCR0) & MMCR0_PMAO) {
		/* This may cause infinite interrupts, so clear it. */
		mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~MMCR0_PMAO);
	}
}

static void test_pmi(void)
{
	report_prefix_push("pmi");
	handle_exception(0x900, &dec_ignore_handler, NULL);
	handle_exception(0xf00, &pmi_handler, NULL);
	reset_mmcr0();
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | MMCR0_PMAO);
	mtmsr(mfmsr() | MSR_EE);
	mtmsr(mfmsr() & ~MSR_EE);
	report(got_interrupt, "PMAO caused interrupt");
	got_interrupt = false;
	handle_exception(0xf00, NULL, NULL);
	handle_exception(0x900, NULL, NULL);
	report_prefix_pop();
}

static void clrbhrb(void)
{
	asm volatile("clrbhrb" ::: "memory");
}

static inline unsigned long mfbhrbe(int nr)
{
	unsigned long e;

	asm volatile("mfbhrbe %0,%1" : "=r"(e) : "i"(nr) : "memory");

	return e;
}

extern unsigned char dummy_branch_1[];
extern unsigned char dummy_branch_2[];

static __attribute__((__noinline__)) void bhrb_dummy(int i)
{
	asm volatile(
	"	cmpdi %0,1	\n\t"
	"	beq 1f		\n\t"
	".global dummy_branch_1	\n\t"
	"dummy_branch_1:	\n\t"
	"	b 2f		\n\t"
	"1:	trap		\n\t"
	".global dummy_branch_2	\n\t"
	"dummy_branch_2:	\n\t"
	"2:	bne 3f		\n\t"
	"	trap		\n\t"
	"3:	nop		\n\t"
	: : "r"(i));
}

#define NR_BHRBE 16
static unsigned long bhrbe[NR_BHRBE];
static int nr_bhrbe;

static void run_and_load_bhrb(void)
{
	int i;

	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~MMCR0_PMAE);
	clrbhrb();
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | MMCR0_BHRBA);
	mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~(MMCR0_FC | MMCR0_FCP | MMCR0_FCPC));
	mtspr(SPR_MMCRA, mfspr(SPR_MMCRA) & ~(MMCRA_BHRBRD | MMCRA_IFM_MASK));

	if (cpu_has_p10_bhrb) {
		mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | MMCR0_PMAE);
		asm volatile("isync" ::: "memory");
		enter_usermode();
		bhrb_dummy(0);
		exit_usermode();
		mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~MMCR0_PMAE);
		asm volatile("isync" ::: "memory");
	} else {
		mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) | MMCR0_PMAE);
		asm volatile("isync" ::: "memory");
		mtmsr(mfmsr());
		asm volatile(".rept 100 ; nop ; .endr");
		bhrb_dummy(0);
		mtspr(SPR_MMCR0, mfspr(SPR_MMCR0) & ~MMCR0_PMAE);
		asm volatile("isync" ::: "memory");
	}

	bhrbe[0] = mfbhrbe(0);
	bhrbe[1] = mfbhrbe(1);
	bhrbe[2] = mfbhrbe(2);
	bhrbe[3] = mfbhrbe(3);
	bhrbe[4] = mfbhrbe(4);
	bhrbe[5] = mfbhrbe(5);
	bhrbe[6] = mfbhrbe(6);
	bhrbe[7] = mfbhrbe(7);
	bhrbe[8] = mfbhrbe(8);
	bhrbe[9] = mfbhrbe(9);
	bhrbe[10] = mfbhrbe(10);
	bhrbe[11] = mfbhrbe(11);
	bhrbe[12] = mfbhrbe(12);
	bhrbe[13] = mfbhrbe(13);
	bhrbe[14] = mfbhrbe(14);
	bhrbe[15] = mfbhrbe(15);

	for (i = 0; i < NR_BHRBE; i++) {
		bhrbe[i] &= ~0x1UL; /* remove prediction bit */
		if (!bhrbe[i])
			break;
	}
	nr_bhrbe = i;
}

static void test_bhrb(void)
{
	int i;

	if (cpu_has_p10_bhrb && !vm_available())
		return;

	report_prefix_push("bhrb");

	/* TCG doesn't impelment BHRB yet */
	handle_exception(0x700, &illegal_handler, NULL);
	handle_exception(0xe40, &illegal_handler, NULL);
	clrbhrb();
	handle_exception(0x700, NULL, NULL);
	handle_exception(0xe40, NULL, NULL);
	if (got_interrupt) {
		got_interrupt = false;
		report_skip("BHRB support missing");
		report_prefix_pop();
		return;
	}

	if (vm_available()) {
		handle_exception(0x900, &dec_ignore_handler, NULL);
		setup_vm();
	}
	reset_mmcr0();
	clrbhrb();
	if (cpu_has_p10_bhrb) {
		enter_usermode();
		bhrb_dummy(0);
		exit_usermode();
	} else {
		bhrb_dummy(0);
	}
	report(mfbhrbe(0) == 0, "BHRB is frozen");

	/*
	 * BHRB may be cleared at any time (e.g., by OS or hypervisor)
	 * so this test could be occasionally incorrect. Try several
	 * times before giving up...
	 */

	if (cpu_has_p10_bhrb) {
		/*
		 * BHRB should have 8 entries:
		 * 1. enter_usermode blr
		 * 2. enter_usermode blr target
		 * 3. bl dummy
		 * 4. dummy unconditional
		 * 5. dummy conditional
		 * 6. dummy blr
		 * 7. dummy blr target
		 * 8. exit_usermode bl
		 *
		 * POWER10 often gives 4 entries, if other threads are
		 * running on the core, it seems to struggle.
		 */
		for (i = 0; i < 200; i++) {
			run_and_load_bhrb();
			if (nr_bhrbe == 8)
				break;
			if (i > 100 && nr_bhrbe == 4)
				break;
		}
		report(nr_bhrbe, "BHRB has been written");
		report_kfail(!host_is_tcg, nr_bhrbe == 8,
			     "BHRB has written 8 entries");
		if (nr_bhrbe == 8) {
			report(bhrbe[4] == (unsigned long)dummy_branch_1,
					"correct unconditional branch address");
			report(bhrbe[3] == (unsigned long)dummy_branch_2,
					"correct conditional branch address");
		} else if (nr_bhrbe == 4) {
			/* POWER10 workaround */
			report(nr_bhrbe == 4, "BHRB has written 4 entries");
			report(bhrbe[3] == (unsigned long)dummy_branch_2,
					"correct conditional branch address");
		}
	} else {
		/*
		 * BHRB should have 6 entries:
		 * 1. bl dummy
		 * 2. dummy unconditional
		 * 3. dummy conditional
		 * 4. dummy blr
		 * 5. dummy blr target
		 * 6. Final b loop before disabled.
		 *
		 * POWER9 often gives 4 entries, if other threads are
		 * running on the core, it seems to struggle.
		 */
		for (i = 0; i < 200; i++) {
			run_and_load_bhrb();
			if (nr_bhrbe == 6)
				break;
			if (i > 100 && nr_bhrbe == 4)
				break;
		}
		report(nr_bhrbe, "BHRB has been written");
		report_kfail(!host_is_tcg, nr_bhrbe == 6,
			     "BHRB has written 6 entries");
		if (nr_bhrbe == 6) {
			report(bhrbe[4] == (unsigned long)dummy_branch_1,
					"correct unconditional branch address");
			report(bhrbe[3] == (unsigned long)dummy_branch_2,
					"correct conditional branch address");
		} else if (nr_bhrbe == 4) {
			/* POWER9 workaround */
			report(nr_bhrbe == 4, "BHRB has written 4 entries");
			report(bhrbe[3] == (unsigned long)dummy_branch_2,
					"correct conditional branch address");
		}
	}

	handle_exception(0x900, NULL, NULL);

	report_prefix_pop();
}

int main(int argc, char **argv)
{
	report_prefix_push("pmu");

	test_pmc56();
	test_pmi();
	if (cpu_has_bhrb)
		test_bhrb();

	report_prefix_pop();

	return report_summary();
}
