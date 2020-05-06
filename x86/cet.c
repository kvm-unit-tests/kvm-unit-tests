
#include "libcflat.h"
#include "x86/desc.h"
#include "x86/processor.h"
#include "x86/vm.h"
#include "x86/msr.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "fault_test.h"


static unsigned char user_stack[0x400];
static unsigned long rbx, rsi, rdi, rsp, rbp, r8, r9,
		     r10, r11, r12, r13, r14, r15;

static unsigned long expected_rip;
static int cp_count;
typedef u64 (*cet_test_func)(void);

cet_test_func func;

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
	 * In below assembly code, the first instruction at lable 2 is not
	 * endbr64, it'll trigger #CP with error code 0x3, and the execution
	 * is terminated when HW detects the violation.
	 */
	printf("No endbr64 instruction at jmp target, this triggers #CP...\n");
	asm volatile ("movq $2, %rcx\n"
		      "dec %rcx\n"
		      "leaq 2f, %rax\n"
		      "jmp *%rax \n"
		      "2:\n"
		      "dec %rcx\n");
	return 0;
}

void test_func(void);
void test_func(void) {
	asm volatile (
			/* IRET into user mode */
			"pushq %[user_ds]\n\t"
			"pushq %[user_stack_top]\n\t"
			"pushfq\n\t"
			"pushq %[user_cs]\n\t"
			"pushq $user_mode\n\t"
			"iretq\n"

			"user_mode:\n\t"
			"call *%[func]\n\t"
			::
			[func]"m"(func),
			[user_ds]"i"(USER_DS),
			[user_cs]"i"(USER_CS),
			[user_stack_top]"r"(user_stack +
					sizeof(user_stack)));
}

#define SAVE_REGS() \
	asm ("movq %%rbx, %0\t\n"  \
	     "movq %%rsi, %1\t\n"  \
	     "movq %%rdi, %2\t\n"  \
	     "movq %%rsp, %3\t\n"  \
	     "movq %%rbp, %4\t\n"  \
	     "movq %%r8, %5\t\n"   \
	     "movq %%r9, %6\t\n"   \
	     "movq %%r10, %7\t\n"  \
	     "movq %%r11, %8\t\n"  \
	     "movq %%r12, %9\t\n"  \
	     "movq %%r13, %10\t\n" \
	     "movq %%r14, %11\t\n" \
	     "movq %%r15, %12\t\n" :: \
	     "m"(rbx), "m"(rsi), "m"(rdi), "m"(rsp), "m"(rbp), \
	     "m"(r8), "m"(r9), "m"(r10),  "m"(r11), "m"(r12),  \
	     "m"(r13), "m"(r14), "m"(r15));

#define RESTOR_REGS() \
	asm ("movq %0, %%rbx\t\n"  \
	     "movq %1, %%rsi\t\n"  \
	     "movq %2, %%rdi\t\n"  \
	     "movq %3, %%rsp\t\n"  \
	     "movq %4, %%rbp\t\n"  \
	     "movq %5, %%r8\t\n"   \
	     "movq %6, %%r9\t\n"   \
	     "movq %7, %%r10\t\n"  \
	     "movq %8, %%r11\t\n"  \
	     "movq %9, %%r12\t\n"  \
	     "movq %10, %%r13\t\n" \
	     "movq %11, %%r14\t\n" \
	     "movq %12, %%r15\t\n" ::\
	     "m"(rbx), "m"(rsi), "m"(rdi), "m"(rsp), "m"(rbp), \
	     "m"(r8), "m"(r9), "m"(r10), "m"(r11), "m"(r12),   \
	     "m"(r13), "m"(r14), "m"(r15));

#define RUN_TEST() \
	do {		\
		SAVE_REGS();    \
		asm volatile ("pushq %%rax\t\n"           \
			      "leaq 1f(%%rip), %%rax\t\n" \
			      "movq %%rax, %0\t\n"        \
			      "popq %%rax\t\n"            \
			      "call test_func\t\n"         \
			      "1:" ::"m"(expected_rip) : "rax", "rdi"); \
		RESTOR_REGS(); \
	} while (0)

#define ENABLE_SHSTK_BIT 0x1
#define ENABLE_IBT_BIT   0x4

static void handle_cp(struct ex_regs *regs)
{
	cp_count++;
	printf("In #CP exception handler, error_code = 0x%lx\n",
		regs->error_code);
	asm("jmp *%0" :: "m"(expected_rip));
}

int main(int ac, char **av)
{
	char *shstk_virt;
	unsigned long shstk_phys;
	unsigned long *ptep;
	pteval_t pte = 0;

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
	setup_idt();
	handle_exception(21, handle_cp);

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
	invlpg((void *)shstk_phys);

	/* Enable shadow-stack protection */
	wrmsr(MSR_IA32_U_CET, ENABLE_SHSTK_BIT);

	/* Store shadow-stack pointer. */
	wrmsr(MSR_IA32_PL3_SSP, (u64)(shstk_virt + 0x1000));

	/* Enable CET master control bit in CR4. */
	write_cr4(read_cr4() | X86_CR4_CET);

	func = cet_shstk_func;
	RUN_TEST();
	report(cp_count == 1, "Completed shadow-stack protection test successfully.");
	cp_count = 0;

	/* Do user-mode indirect-branch-tracking test.*/
	func = cet_ibt_func;
	/* Enable indirect-branch tracking */
	wrmsr(MSR_IA32_U_CET, ENABLE_IBT_BIT);

	RUN_TEST();
	report(cp_count == 1, "Completed Indirect-branch tracking test successfully.");

	write_cr4(read_cr4() & ~X86_CR4_CET);
	wrmsr(MSR_IA32_U_CET, 0);

	return report_summary();
}
