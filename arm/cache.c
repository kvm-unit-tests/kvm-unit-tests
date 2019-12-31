#include <libcflat.h>
#include <alloc_page.h>
#include <asm/mmu.h>
#include <asm/processor.h>
#include <asm/thread_info.h>

#define NTIMES			(1 << 16)

#define CTR_DIC			(1UL << 29)
#define CTR_IDC			(1UL << 28)

#define CLIDR_LOC_SHIFT		24
#define CLIDR_LOC_MASK		(7UL << CLIDR_LOC_SHIFT)
#define CLIDR_LOUU_SHIFT	27
#define CLIDR_LOUU_MASK		(7UL << CLIDR_LOUU_SHIFT)
#define CLIDR_LOUIS_SHIFT	21
#define CLIDR_LOUIS_MASK	(7UL << CLIDR_LOUIS_SHIFT)

#define RET			0xd65f03c0
#define MOV_X0(x)		(0xd2800000 | (((x) & 0xffff) << 5))

#define clean_dcache_pou(addr)			\
	asm volatile("dc cvau, %0\n" :: "r" (addr) : "memory")
#define inval_icache_pou(addr)			\
	asm volatile("ic ivau, %0\n" :: "r" (addr) : "memory")

typedef int (*fn_t)(void);

static inline void prime_icache(u32 *code, u32 insn)
{
	*code = insn;
	/* This is the sequence recommended in ARM DDI 0487E.a, page B2-136. */
	clean_dcache_pou(code);
	dsb(ish);
	inval_icache_pou(code);
	dsb(ish);
	isb();

	((fn_t)code)();
}

static void check_code_generation(bool dcache_clean, bool icache_inval)
{
	u32 fn[] = {MOV_X0(0x42), RET};
	u32 *code = alloc_page();
	unsigned long sctlr;
	int i, ret;
	bool success;

	/* Make sure we can execute from a writable page */
	mmu_clear_user(current_thread_info()->pgtable, (unsigned long)code);

	sctlr = read_sysreg(sctlr_el1);
	if (sctlr & SCTLR_EL1_WXN) {
		sctlr &= ~SCTLR_EL1_WXN;
		write_sysreg(sctlr, sctlr_el1);
		isb();
		/* SCTLR_EL1.WXN is permitted to be cached in a TLB. */
		flush_tlb_all();
	}

	for (i = 0; i < ARRAY_SIZE(fn); i++) {
		*(code + i) = fn[i];
		clean_dcache_pou(code + i);
		dsb(ish);
		inval_icache_pou(code + i);
	}
	dsb(ish);
	isb();

	/* Sanity check */
	((fn_t)code)();

	success = true;
	for (i = 0; i < NTIMES; i++) {
		prime_icache(code, MOV_X0(0x42));
		*code = MOV_X0(0x66);
		if (dcache_clean)
			clean_dcache_pou(code);
		if (icache_inval) {
			if (dcache_clean)
				dsb(ish);
			inval_icache_pou(code);
		}
		dsb(ish);
		isb();

		ret = ((fn_t)code)();
		success &= (ret == 0x66);
	}

	report(success, "code generation");
}

int main(int argc, char **argv)
{
	u64 ctr, clidr;
	bool dcache_clean, icache_inval;

	report_prefix_push("IDC-DIC");

	ctr = read_sysreg(ctr_el0);
	dcache_clean = !(ctr & CTR_IDC);
	icache_inval = !(ctr & CTR_DIC);

	if (dcache_clean) {
		clidr = read_sysreg(clidr_el1);
		if ((clidr & CLIDR_LOC_MASK) == 0)
			dcache_clean = false;
		if ((clidr & CLIDR_LOUU_MASK) == 0 &&
		    (clidr & CLIDR_LOUIS_MASK) == 0)
			dcache_clean = false;
	}

	if (dcache_clean)
		report_info("dcache clean to PoU required");
	if (icache_inval)
		report_info("icache invalidation to PoU required");

	check_code_generation(dcache_clean, icache_inval);

	return report_summary();
}
