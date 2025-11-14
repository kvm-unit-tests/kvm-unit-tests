
#include "libcflat.h"
#include "x86/desc.h"
#include "x86/processor.h"
#include "x86/vm.h"
#include "x86/msr.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "fault_test.h"

static int cp_count;
static unsigned long invalid_offset = 0xffffffffffffff;

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

static void handle_cp(struct ex_regs *regs)
{
	cp_count++;
	printf("In #CP exception handler, error_code = 0x%lx\n",
		regs->error_code);
	/* Below jmp is expected to trigger #GP */
	asm("jmpq *%0": :"m"(invalid_offset));
}

int main(int ac, char **av)
{
	char *shstk_virt;
	unsigned long shstk_phys;
	unsigned long *ptep;
	pteval_t pte = 0;
	bool rvc;

	cp_count = 0;
	if (!this_cpu_has(X86_FEATURE_SHSTK)) {
		printf("SHSTK not enabled\n");
		return report_summary();
	}

	if (!this_cpu_has(X86_FEATURE_IBT)) {
		printf("IBT not enabled\n");
		return report_summary();
	}

	setup_vm();
	handle_exception(CP_VECTOR, handle_cp);

	/* Allocate one page for shadow-stack. */
	shstk_virt = alloc_vpage();
	shstk_phys = (unsigned long)virt_to_phys(alloc_page());

	/* Install the new page. */
	pte = shstk_phys | PT_PRESENT_MASK | PT_WRITABLE_MASK | PT_USER_MASK;
	install_pte(current_page_table(), 1, shstk_virt, pte, 0);
	memset(shstk_virt, 0x0, PAGE_SIZE);

	/* Mark it as shadow-stack page. */
	ptep = get_pte_level(current_page_table(), shstk_virt, 1);
	*ptep &= ~PT_WRITABLE_MASK;
	*ptep |= PT_DIRTY_MASK;

	/* Flush the paging cache. */
	invlpg((void *)shstk_virt);

	/* Enable shadow-stack protection */
	wrmsr(MSR_IA32_U_CET, ENABLE_SHSTK_BIT);

	/* Store shadow-stack pointer. */
	wrmsr(MSR_IA32_PL3_SSP, (u64)(shstk_virt + 0x1000));

	/* Enable CET master control bit in CR4. */
	write_cr4(read_cr4() | X86_CR4_CET);

	printf("Unit test for CET user mode...\n");
	run_in_user((usermode_func)cet_shstk_func, GP_VECTOR, 0, 0, 0, 0, &rvc);
	report(cp_count == 1, "Completed shadow-stack protection test successfully.");
	cp_count = 0;

	/* Enable indirect-branch tracking */
	wrmsr(MSR_IA32_U_CET, ENABLE_IBT_BIT);

	run_in_user((usermode_func)cet_ibt_func, GP_VECTOR, 0, 0, 0, 0, &rvc);
	report(cp_count == 1, "Completed Indirect-branch tracking test successfully.");

	write_cr4(read_cr4() & ~X86_CR4_CET);
	wrmsr(MSR_IA32_U_CET, 0);

	return report_summary();
}
