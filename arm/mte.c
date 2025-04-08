/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Arm Limited.
 * All rights reserved.
 */

#include <libcflat.h>
#include <alloc_page.h>
#include <stdlib.h>

#include <asm/mmu.h>
#include <asm/pgtable-hwdef.h>
#include <asm/processor.h>
#include <asm/sysreg.h>
#include <asm/thread_info.h>


/* Tag Check Faults cause a synchronous exception */
#define MTE_TCF_SYNC	0b01
/* Tag Check Faults are asynchronously accumulated */
#define MTE_TCF_ASYNC	0b10
/*
 * Tag Check Faults cause a synchronous exception on reads,
 * and are asynchronously accumulated on writes
 */
#define MTE_TCF_ASYMM	0b11

#define MTE_GRANULE_SIZE        UL(16)
#define MTE_GRANULE_MASK        (~(MTE_GRANULE_SIZE - 1))
#define MTE_TAG_SHIFT           56

#define untagged(p)									\
({											\
	unsigned long __in = (unsigned long)(p);					\
	typeof(p) __out = (typeof(p))(__in & ~(MTE_GRANULE_MASK << MTE_TAG_SHIFT));	\
											\
	__out;										\
})

#define tagged(p, t)							\
({									\
	unsigned long __in = (unsigned long)(untagged(p));		\
	unsigned long __tag = (unsigned long)(t) << MTE_TAG_SHIFT;	\
	typeof(p) __out = (typeof(p))(__in | __tag);			\
									\
	__out;								\
})

/*
 * If we use a normal (non hand coded inline assembly) load or store
 * to access a tagged address, the compiler will reasonably assume
 * that the access succeeded, and the next instruction may do
 * something based on that assumption.
 *
 * But a test might want the tagged access to fail on purpose, and if
 * we advance the PC to the next instruction, the one added by the
 * compiler, we might leave the program in an unexpected state.
 */
static inline void mem_read(unsigned int *addr, unsigned int *res)
{
	unsigned int r;

	asm volatile ("ldr %w0,[%1]\n"
		      "str %w0,[%2]\n"
		      : "=&r" (r)
		      : "r" (addr), "r" (res) : "memory");
}

static inline void mem_write(unsigned int *addr, unsigned int val)
{
	/* The NOP allows the same exception handler as mem_read() to be used. */
	asm volatile ("str %w0,[%1]\n"
		      "nop\n"
		      :
		      : "r" (val), "r" (addr)
		      : "memory");
}

static volatile bool mte_exception;

static void mte_fault_handler(struct pt_regs *regs, unsigned int esr)
{
	unsigned int dfsc = esr & GENMASK(5, 0);
	unsigned int fnv = esr & BIT(10);

	if (dfsc == 0b010001) {
		if (fnv)
			report_info("Unexpected non-zero FnV");
		mte_exception = true;
	}

	/*
	 * mem_read() reads the value from the tagged pointer, then
	 * stores this value in the untagged 'res' pointer. The
	 * function that called mem_read() will want to check that the
	 * initial value of 'res' hasn't changed if a tag check fault
	 * is reported. Skip over two instructions so 'res' isn't
	 * overwritten.
	 */
	regs->pc += 8;
}

static inline void mmu_set_tagged(pgd_t *pgtable, unsigned long vaddr)
{
	pteval_t *p_pte = follow_pte(pgtable, untagged(vaddr));

	if (p_pte) {
		pteval_t entry = *p_pte;

		entry &= ~PTE_ATTRINDX_MASK;
		entry |= PTE_ATTRINDX(MT_NORMAL_TAGGED);

		WRITE_ONCE(*p_pte, entry);
		flush_tlb_page(vaddr);
	} else {
		report_abort("Cannot find PTE");
	}
}

static void mte_init(void)
{
	unsigned long sctlr = read_sysreg(sctlr_el1);
	unsigned long tcr = read_sysreg(tcr_el1);

	sctlr &= ~SCTLR_EL1_TCF_MASK;
	sctlr |= SCTLR_EL1_ATA;

	tcr &= ~TCR_TCMA0;
	tcr |= TCR_TBI0;

	write_sysreg(sctlr, sctlr_el1);
	write_sysreg(tcr, tcr_el1);

	isb();
	flush_tlb_all();
}

static inline unsigned long mte_set_tcf(unsigned long tcf)
{
	unsigned long sctlr = read_sysreg(sctlr_el1);
	unsigned long old = (sctlr & SCTLR_EL1_TCF_MASK) >> SCTLR_EL1_TCF_SHIFT;

	sctlr &= ~(SCTLR_EL1_TCF_MASK | SCTLR_EL1_TCF0_MASK);
	sctlr |= (tcf << SCTLR_EL1_TCF_SHIFT) & SCTLR_EL1_TCF_MASK;

	write_sysreg(sctlr, sctlr_el1);
	write_sysreg_s(0, TFSR_EL1);
	isb();

	return old;
}

static inline void mte_set_tag(void *addr, size_t size, unsigned int tag)
{
#ifdef CC_HAS_MTE
	unsigned long in = (unsigned long)untagged(addr);
	unsigned long start = ALIGN_DOWN(in, 16);
	unsigned long end = ALIGN(in + size, 16);

	for (unsigned long ptr = start; ptr < end; ptr += 16) {
		asm volatile(".arch   armv8.5-a+memtag\n"
			     "stg %0, [%0]"
			     :
			     : "r"(tagged(ptr, tag))
			     : "memory");
	}
#endif
}

static inline unsigned long get_clear_tfsr(void)
{
	unsigned long r;

	dsb(nsh);
	isb();

	r = read_sysreg_s(TFSR_EL1);
	write_sysreg_s(0, TFSR_EL1);

	return r;
}

static void mte_sync_test(void)
{
	unsigned int *mem = tagged(alloc_page(), 1);
	unsigned int val = 0;

	mmu_set_tagged(current_thread_info()->pgtable, (unsigned long)mem);
	mte_set_tag(mem, PAGE_SIZE, 1);
	memset(mem, 0xff, PAGE_SIZE);
	mte_set_tcf(MTE_TCF_SYNC);

	mte_exception = false;

	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_DABT_EL1, mte_fault_handler);

	mem_read(tagged(mem, 2), &val);

	report((val == 0) && mte_exception && (get_clear_tfsr() == 0), "read");

	mte_exception = false;

	mem_write(tagged(mem, 3), 0xbbbbbbbb);

	report((*mem == 0xffffffff) && mte_exception && (get_clear_tfsr() == 0), "write");

	free_page(untagged(mem));
}

static void mte_asymm_test(void)
{
	unsigned int *mem = tagged(alloc_page(), 2);
	unsigned int val = 0;

	mmu_set_tagged(current_thread_info()->pgtable, (unsigned long)mem);
	mte_set_tag(mem, PAGE_SIZE, 2);
	memset(mem, 0xff, PAGE_SIZE);
	mte_set_tcf(MTE_TCF_ASYMM);
	mte_exception = false;

	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_DABT_EL1, mte_fault_handler);

	mem_read(tagged(mem, 3), &val);
	report((val == 0) && mte_exception && (get_clear_tfsr() == 0), "read");

	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_DABT_EL1, NULL);

	mem_write(tagged(mem, 4), 0xaaaaaaaa);
	report((*mem == 0xaaaaaaaa) && (get_clear_tfsr() == TFSR_EL1_TF0), "write");

	free_page(untagged(mem));
}

static void mte_async_test(void)
{
	unsigned int *mem = tagged(alloc_page(), 3);
	unsigned int val = 0;

	mmu_set_tagged(current_thread_info()->pgtable, (unsigned long)mem);
	mte_set_tag(mem, PAGE_SIZE, 3);
	memset(mem, 0xff, PAGE_SIZE);
	mte_set_tcf(MTE_TCF_ASYNC);

	mem_read(tagged(mem, 4), &val);
	report((val == 0xffffffff) && (get_clear_tfsr() == TFSR_EL1_TF0), "read");

	mem_write(tagged(mem, 5), 0xcccccccc);
	report((*mem == 0xcccccccc) && (get_clear_tfsr() == TFSR_EL1_TF0), "write");

	free_page(untagged(mem));
}

static unsigned int mte_version(void)
{
#ifdef CC_HAS_MTE
	uint64_t r;

	asm volatile("mrs %x0, id_aa64pfr1_el1" : "=r"(r));

	return (r >> ID_AA64PFR1_EL1_MTE_SHIFT) & 0b1111;
#else
	report_info("Compiler lack MTE support");
	return 0;
#endif
}

int main(int argc, char *argv[])
{

	unsigned int version = mte_version();

	if (version < 2) {
		report_skip("No MTE support, skip...\n");
		return report_summary();
	}

	if (argc < 2)
		report_abort("no test specified");

	report_prefix_push("mte");

	mte_init();

	if (strcmp(argv[1], "sync") == 0) {
		report_prefix_push(argv[1]);
		mte_sync_test();
		report_prefix_pop();
	} else if (strcmp(argv[1], "async") == 0) {
		report_prefix_push(argv[1]);
		if (version < 3) {
			report_skip("No MTE async, skip...\n");
			return report_summary();
		}
		mte_async_test();
		report_prefix_pop();
	} else if (strcmp(argv[1], "asymm") == 0) {
		report_prefix_push(argv[1]);
		if (version < 3) {
			report_skip("No MTE asymm, skip...\n");
			return report_summary();
		}
		mte_asymm_test();
		report_prefix_pop();
	} else {
		report_abort("Unknown sub-test '%s'", argv[1]);
	}

	return report_summary();
}
