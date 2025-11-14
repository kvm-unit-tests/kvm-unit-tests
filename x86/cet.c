#include "libcflat.h"
#include "x86/desc.h"
#include "x86/processor.h"
#include "x86/vm.h"
#include "x86/msr.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "fault_test.h"

static uint64_t cet_shstk_func(void)
{
	unsigned long *ret_addr = __builtin_frame_address(0) + sizeof(void *);
	unsigned long *ssp;

	/* rdsspq %rax */
	asm volatile (".byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8" : "=a"(ssp));

	printf("The return-address in shadow-stack = 0x%lx, in normal stack = 0x%lx\n",
	       *ssp, *ret_addr);

	/*
	 * In below line, it modifies the return address, it'll trigger #CP
	 * while function is returning. The error-code is 0x1, meaning it's
	 * caused by a near RET instruction, and the execution is terminated
	 * when HW detects the violation.
	 */
	printf("Try to temper the return-address, this causes #CP on returning...\n");
	*(volatile unsigned long *)ret_addr ^= 0xdeaddead;

	return 0;
}

static uint64_t cet_shstk_far_ret(void)
{
	struct far_pointer32 fp = {
		.offset = (uintptr_t)&&far_func,
		.selector = USER_CS,
	};

	if (fp.offset != (uintptr_t)&&far_func) {
		printf("Code address too high.\n");
		return -1;
	}

	printf("Try to temper the return-address of far-called function...\n");

	/* The NOP isn't superfluous, the called function tries to skip it. */
	asm goto ("lcall *%0; nop" : : "m" (fp) : : far_func);

	printf("Uhm... how did we get here?! This should have #CP'ed!\n");

	return 0;
far_func:
	asm volatile (/* mess with the ret addr, make it point past the NOP */
		      "incq (%rsp)\n\t"
		      /* 32-bit return, just as we have been called */
		      "lretl");
	__builtin_unreachable();
}

static uint64_t cet_ibt_func(void)
{
	unsigned long tmp;
	/*
	 * In below assembly code, the first instruction at label 2 is not
	 * endbr64, it'll trigger #CP with error code 0x3, and the execution
	 * is terminated when HW detects the violation.
	 */
	printf("No endbr64 instruction at jmp target, this triggers #CP...\n");
	asm volatile ("leaq 2f(%%rip), %0\n\t"
		      "jmpq *%0\n\t"
		      "2:"
		      : "=r"(tmp));
	return 0;
}

#define __CET_TEST_UNSUPPORTED_INSTRUCTION(insn)			\
({									\
	struct far_pointer32 fp = {					\
		.offset = 0,						\
		.selector = USER_CS,					\
	};								\
									\
	asm volatile ("push %%rax\n"					\
		      ASM_TRY_FEP("1f") insn "\n\t"			\
		      "1:"						\
		      "pop %%rax\n"					\
		      : : "m" (fp), "a" (NONCANONICAL) : "memory");	\
									\
	exception_vector();					\
})

#define SHSTK_TEST_UNSUPPORTED_INSTRUCTION(insn)			\
do {									\
	uint8_t vector = __CET_TEST_UNSUPPORTED_INSTRUCTION(insn);	\
									\
	report(vector == UD_VECTOR, "SHSTK: Wanted #UD on %s, got %s",	\
	       insn, exception_mnemonic(vector));			\
} while (0)

/*
 * Treat IRET as unsupported with IBT even though the minimal interactions with
 * IBT _could_ be easily emulated by KVM, as KVM doesn't support emulating IRET
 * outside of Real Mode.
 */
#define CET_TEST_UNSUPPORTED_INSTRUCTIONS(CET)				\
do {									\
	CET##_TEST_UNSUPPORTED_INSTRUCTION("callq *%%rax");		\
	CET##_TEST_UNSUPPORTED_INSTRUCTION("lcall *%0");		\
	CET##_TEST_UNSUPPORTED_INSTRUCTION("syscall");			\
	CET##_TEST_UNSUPPORTED_INSTRUCTION("sysenter");			\
	CET##_TEST_UNSUPPORTED_INSTRUCTION("iretq");			\
} while (0)

static uint64_t cet_shstk_emulation(void)
{
	CET_TEST_UNSUPPORTED_INSTRUCTIONS(SHSTK);

	SHSTK_TEST_UNSUPPORTED_INSTRUCTION("call 1f");
	SHSTK_TEST_UNSUPPORTED_INSTRUCTION("retq");
	SHSTK_TEST_UNSUPPORTED_INSTRUCTION("retq $10");
	SHSTK_TEST_UNSUPPORTED_INSTRUCTION("lretq");
	SHSTK_TEST_UNSUPPORTED_INSTRUCTION("lretq $10");

	/* Do a handful of JMPs to verify they aren't impacted by SHSTK. */
	asm volatile(KVM_FEP "jmp 1f\n\t"
		     "1:\n\t"
		     KVM_FEP "lea 2f(%%rip), %%rax\n\t"
		     KVM_FEP "jmp *%%rax\n\t"
		     "2:\n\t"
		     KVM_FEP "push $" xstr(USER_CS) "\n\t"
		     KVM_FEP "lea 3f(%%rip), %%rax\n\t"
		     KVM_FEP "push %%rax\n\t"
		     /*
		      * Manually encode ljmpq, which gas doesn't recognize due
		      * to AMD not supporting the instruction (64-bit JMP FAR).
		      */
		     KVM_FEP ".byte 0x48\n\t"
		     "ljmpl *(%%rsp)\n\t"
		     "3:\n\t"
		     KVM_FEP "pop %%rax\n\t"
		     KVM_FEP "pop %%rax\n\t"
		     ::: "eax");

	return 0;
}

#define IBT_TEST_UNSUPPORTED_INSTRUCTION(insn)				\
do {									\
	uint8_t vector = __CET_TEST_UNSUPPORTED_INSTRUCTION(insn);	\
									\
	report(vector == UD_VECTOR, "IBT: Wanted #UD on %s, got %s",	\
	       insn, exception_mnemonic(vector));			\
} while (0)

static uint64_t cet_ibt_emulation(void)
{
	CET_TEST_UNSUPPORTED_INSTRUCTIONS(IBT);

	IBT_TEST_UNSUPPORTED_INSTRUCTION("jmp *%%rax");
	IBT_TEST_UNSUPPORTED_INSTRUCTION("ljmpl *%0");

	/* Verify direct CALLs and JMPs, and all RETs aren't impacted by IBT. */
	asm volatile(KVM_FEP "jmp 2f\n\t"
		     "1: " KVM_FEP " ret\n\t"
		     "2: " KVM_FEP " call 1b\n\t"
		     KVM_FEP "push $" xstr(USER_CS) "\n\t"
		     KVM_FEP "lea 3f(%%rip), %%rax\n\t"
		     KVM_FEP "push %%rax\n\t"
		     KVM_FEP "lretq\n\t"
		     "3:\n\t"
		     KVM_FEP "push $0x55555555\n\t"
		     KVM_FEP "push $" xstr(USER_CS) "\n\t"
		     KVM_FEP "lea 4f(%%rip), %%rax\n\t"
		     KVM_FEP "push %%rax\n\t"
		     KVM_FEP "lretq $8\n\t"
		     "4:\n\t"
		     ::: "eax");
	return 0;
}

#define CP_ERR_NEAR_RET	0x0001
#define CP_ERR_FAR_RET	0x0002
#define CP_ERR_ENDBR	0x0003
#define CP_ERR_RSTORSSP	0x0004
#define CP_ERR_SETSSBSY	0x0005
#define CP_ERR_ENCL		BIT(15)

#define CET_ENABLE_SHSTK			BIT(0)
#define CET_ENABLE_IBT				BIT(2)
#define CET_ENABLE_NOTRACK			BIT(4)
#define CET_IBT_SUPPRESS			BIT(10)
#define CET_IBT_TRACKER_WAIT_FOR_ENDBRANCH	BIT(11)

static void test_shstk(void)
{
	char *shstk_virt;
	unsigned long shstk_phys;
	pteval_t pte = 0;
	u8 vector;
	bool rvc;

	if (!this_cpu_has(X86_FEATURE_SHSTK)) {
		report_skip("SHSTK not supported");
		return;
	}

	/* Allocate one page for shadow-stack. */
	shstk_virt = alloc_vpage();
	shstk_phys = (unsigned long)virt_to_phys(alloc_page());

	/*
	 * Install a mapping for the shadow stack page.  Shadow stack pages are
	 * denoted by an "impossible" combination of a !WRITABLE, DIRTY PTE
	 * (writes from CPU for shadow stack operations are allowed, but writes
	 * from software are not).
	 */
	pte = shstk_phys | PT_PRESENT_MASK | PT_USER_MASK | PT_DIRTY_MASK;
	install_pte(current_page_table(), 1, shstk_virt, pte, 0);

	/* Enable shadow-stack protection */
	wrmsr(MSR_IA32_U_CET, CET_ENABLE_SHSTK);

	/* Store shadow-stack pointer. */
	wrmsr(MSR_IA32_PL3_SSP, (u64)(shstk_virt + 0x1000));

	printf("Running user mode Shadow Stack tests\n");
	run_in_user(cet_shstk_func, CP_VECTOR, 0, 0, 0, 0, &rvc);
	report(rvc && exception_error_code() == CP_ERR_NEAR_RET,
	       "NEAR RET shadow-stack protection test");

	run_in_user(cet_shstk_far_ret, CP_VECTOR, 0, 0, 0, 0, &rvc);
	report(rvc && exception_error_code() == CP_ERR_FAR_RET,
	       "FAR RET shadow-stack protection test");

	if (is_fep_available &&
	    (run_in_user(cet_shstk_emulation, CP_VECTOR, 0, 0, 0, 0, &rvc) || rvc))
		report_fail("Forced emulation with SHSTK generated %s(%u)",
			    exception_mnemonic(exception_vector()),
			    exception_error_code());

	/* SSP should be 4-Byte aligned */
	vector = wrmsr_safe(MSR_IA32_PL3_SSP, 0x1);
	report(vector == GP_VECTOR, "MSR_IA32_PL3_SSP alignment test.");
}

static void ibt_tracker_cp_fixup(struct ex_regs *regs)
{
	u64 cet_u = rdmsr(MSR_IA32_U_CET);

	/*
	 * Switch the IBT tracker state to IDLE to have a clean state for
	 * following tests.
	 */
	if (cet_u & CET_IBT_TRACKER_WAIT_FOR_ENDBRANCH) {
		cet_u &= ~CET_IBT_TRACKER_WAIT_FOR_ENDBRANCH;
		printf("CET: suppressing IBT WAIT_FOR_ENDBRANCH state at RIP: %lx\n",
		       regs->rip);
		wrmsr(MSR_IA32_U_CET, cet_u);
	}
}

static uint64_t ibt_run_in_user(usermode_func func, bool *got_cp)
{
	return run_in_user_ex(func, CP_VECTOR, 0, 0, 0, 0, got_cp,
			      ibt_tracker_cp_fixup);
}

static void test_ibt(void)
{
	bool got_cp;

	if (!this_cpu_has(X86_FEATURE_IBT)) {
		report_skip("IBT not supported");
		return;
	}

	/* Enable indirect-branch tracking (notrack handling for jump tables) */
	wrmsr(MSR_IA32_U_CET, CET_ENABLE_IBT | CET_ENABLE_NOTRACK);

	ibt_run_in_user(cet_ibt_func, &got_cp);
	report(got_cp && exception_error_code() == CP_ERR_ENDBR,
	       "Indirect-branch tracking test");

	if (is_fep_available &&
	    (ibt_run_in_user(cet_ibt_emulation, &got_cp) || got_cp))
		report_fail("Forced emulation with IBT generated %s(%u)",
			    exception_mnemonic(exception_vector()),
			    exception_error_code());
}

int main(int ac, char **av)
{
	if (!this_cpu_has(X86_FEATURE_SHSTK) && !this_cpu_has(X86_FEATURE_IBT)) {
		report_skip("No CET features supported");
		return report_summary();
	}

	setup_vm();

	/* Enable CET global control bit in CR4. */
	write_cr4(read_cr4() | X86_CR4_CET);

	test_shstk();
	test_ibt();

	write_cr4(read_cr4() & ~X86_CR4_CET);
	wrmsr(MSR_IA32_U_CET, 0);

	return report_summary();
}
