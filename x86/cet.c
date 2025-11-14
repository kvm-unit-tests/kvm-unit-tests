
#include "libcflat.h"
#include "x86/desc.h"
#include "x86/processor.h"
#include "x86/vm.h"
#include "x86/msr.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "fault_test.h"

static u64 cet_shstk_func(void)
{
	unsigned long *ret_addr, *ssp;

	/* rdsspq %rax */
	asm volatile (".byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8" : "=a"(ssp));

	asm("movq %%rbp,%0" : "=r"(ret_addr));
	printf("The return-address in shadow-stack = 0x%lx, in normal stack = 0x%lx\n",
	       *ssp, *(ret_addr + 1));

	/*
	 * In below line, it modifies the return address, it'll trigger #CP
	 * while function is returning. The error-code is 0x1, meaning it's
	 * caused by a near RET instruction, and the execution is terminated
	 * when HW detects the violation.
	 */
	printf("Try to temper the return-address, this causes #CP on returning...\n");
	*(ret_addr + 1) = 0xdeaddead;

	return 0;
}

static u64 cet_ibt_func(void)
{
	/*
	 * In below assembly code, the first instruction at label 2 is not
	 * endbr64, it'll trigger #CP with error code 0x3, and the execution
	 * is terminated when HW detects the violation.
	 */
	printf("No endbr64 instruction at jmp target, this triggers #CP...\n");
	asm volatile ("movq $2, %rcx\n"
		      "dec %rcx\n"
		      "leaq 2f(%rip), %rax\n"
		      "jmp *%rax \n"
		      "2:\n"
		      "dec %rcx\n");
	return 0;
}

#define ENABLE_SHSTK_BIT 0x1
#define ENABLE_IBT_BIT   0x4

int main(int ac, char **av)
{
	char *shstk_virt;
	unsigned long shstk_phys;
	pteval_t pte = 0;
	bool rvc;

	if (!this_cpu_has(X86_FEATURE_SHSTK)) {
		report_skip("SHSTK not enabled");
		return report_summary();
	}

	if (!this_cpu_has(X86_FEATURE_IBT)) {
		report_skip("IBT not enabled");
		return report_summary();
	}

	setup_vm();

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
	wrmsr(MSR_IA32_U_CET, ENABLE_SHSTK_BIT);

	/* Store shadow-stack pointer. */
	wrmsr(MSR_IA32_PL3_SSP, (u64)(shstk_virt + 0x1000));

	/* Enable CET master control bit in CR4. */
	write_cr4(read_cr4() | X86_CR4_CET);

	printf("Unit test for CET user mode...\n");
	run_in_user((usermode_func)cet_shstk_func, CP_VECTOR, 0, 0, 0, 0, &rvc);
	report(rvc && exception_error_code() == 1, "Shadow-stack protection test.");

	/* Enable indirect-branch tracking */
	wrmsr(MSR_IA32_U_CET, ENABLE_IBT_BIT);

	run_in_user((usermode_func)cet_ibt_func, CP_VECTOR, 0, 0, 0, 0, &rvc);
	report(rvc && exception_error_code() == 3, "Indirect-branch tracking test.");

	write_cr4(read_cr4() & ~X86_CR4_CET);
	wrmsr(MSR_IA32_U_CET, 0);

	return report_summary();
}
