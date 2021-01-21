#include "libcflat.h"
#include <alloc_page.h>
#include "x86/desc.h"
#include "x86/processor.h"
#include "x86/vm.h"

volatile int pf_count = 0;
volatile int save;
volatile unsigned test;

void do_pf_tss(unsigned long error_code);

// When doing ring 3 tests, page fault handlers will always run on a
// separate stack (the ring 0 stack).  Seems easier to use the alt_stack
// mechanism for both ring 0 and ring 3.

void do_pf_tss(unsigned long error_code)
{
	pf_count++;
	save = test;

#ifndef __x86_64__
	tss.eflags |= X86_EFLAGS_AC;
#endif
}

extern void pf_tss(void);
asm ("pf_tss:\n"
#ifdef __x86_64__
        // no task on x86_64, save/restore caller-save regs
        "push %rax; push %rcx; push %rdx; push %rsi; push %rdi\n"
        "push %r8; push %r9; push %r10; push %r11\n"
	"mov 9*8(%rsp),%rdi\n"
#endif
	"call do_pf_tss\n"
#ifdef __x86_64__
        "pop %r11; pop %r10; pop %r9; pop %r8\n"
        "pop %rdi; pop %rsi; pop %rdx; pop %rcx; pop %rax\n"
#endif
	"add $"S", %"R "sp\n"
#ifdef __x86_64__
	"orl $" xstr(X86_EFLAGS_AC) ", 2*"S"(%"R "sp)\n"  // set EFLAGS.AC and retry
#endif
        "iret"W" \n\t"
        "jmp pf_tss\n\t");


#define USER_BASE	(1 << 23)
#define USER_VAR(v)	(*((__typeof__(&(v))) (((unsigned long)&v) + USER_BASE)))
#define USER_ADDR(v)   ((void *)((unsigned long)(&v) + USER_BASE))

static void init_test(int i)
{
	pf_count = 0;
	if (i) {
		invlpg(&test);
		invlpg(&USER_VAR(test));
	}
}

static void check_smap_nowp(void)
{
	test = 0x99;

	*get_pte(phys_to_virt(read_cr3()), USER_ADDR(test)) &= ~PT_WRITABLE_MASK;

	write_cr4(read_cr4() & ~X86_CR4_SMAP);
	write_cr0(read_cr0() & ~X86_CR0_WP);
	clac();
	write_cr3(read_cr3());

	init_test(0);
	USER_VAR(test) = 0x99;
	report(pf_count == 0,
	       "write from user page with SMAP=0, AC=0, WP=0, PTE.U=1 && PTE.W=0");

	write_cr4(read_cr4() | X86_CR4_SMAP);
	write_cr3(read_cr3());

	init_test(0);
	(void)USER_VAR(test);
	report(pf_count == 1 && save == 0x99,
	       "read from user page with SMAP=1, AC=0, WP=0, PTE.U=1 && PTE.W=0");

	/* Undo changes */
	*get_pte(phys_to_virt(read_cr3()), USER_ADDR(test)) |= PT_WRITABLE_MASK;

	write_cr0(read_cr0() | X86_CR0_WP);
	write_cr3(read_cr3());
}

int main(int ac, char **av)
{
	unsigned long i;

	if (!this_cpu_has(X86_FEATURE_SMAP)) {
		printf("SMAP not enabled\n");
		return report_summary();
	}

	setup_vm();
	setup_alt_stack();
	set_intr_alt_stack(14, pf_tss);

	if (reserve_pages(USER_BASE, USER_BASE >> 12))
		report_abort("Could not reserve memory");
	// Map first 8MB as supervisor pages
	for (i = 0; i < USER_BASE; i += PAGE_SIZE) {
		*get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) &= ~PT_USER_MASK;
		invlpg((void *)i);
	}

	// Present the same 8MB as user pages in the 8MB-16MB range
	for (i = USER_BASE; i < 2 * USER_BASE; i += PAGE_SIZE) {
		*get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) &= ~USER_BASE;
		invlpg((void *)i);
	}

	clac();
	write_cr4(read_cr4() | X86_CR4_SMAP);
	write_cr3(read_cr3());

	for (i = 0; i < 2; i++) {
		if (i)
			printf("testing with INVLPG\n");
		else
			printf("testing without INVLPG\n");

		init_test(i);
		clac();
		test = 42;
		report(pf_count == 0 && test == 42,
		       "write to supervisor page");

		init_test(i);
		stac();
		(void)USER_VAR(test);
		report(pf_count == 0, "read from user page with AC=1");

		init_test(i);
		clac();
		(void)USER_VAR(test);
		report(pf_count == 1 && save == 42,
		       "read from user page with AC=0");

		init_test(i);
		stac();
		save = 0;
		USER_VAR(test) = 43;
		report(pf_count == 0 && test == 43,
		       "write to user page with AC=1");

		init_test(i);
		clac();
		USER_VAR(test) = 44;
		report(pf_count == 1 && test == 44 && save == 43,
		       "read from user page with AC=0");

		init_test(i);
		stac();
		test = -1;
		asm("or $(" xstr(USER_BASE) "), %"R "sp \n"
		    "push $44 \n "
		    "decl test\n"
		    "and $~(" xstr(USER_BASE) "), %"R "sp \n"
		    "pop %"R "ax\n"
		    "movl %eax, test");
		report(pf_count == 0 && test == 44,
		       "write to user stack with AC=1");

		init_test(i);
		clac();
		test = -1;
		asm("or $(" xstr(USER_BASE) "), %"R "sp \n"
		    "push $45 \n "
		    "decl test\n"
		    "and $~(" xstr(USER_BASE) "), %"R "sp \n"
		    "pop %"R "ax\n"
		    "movl %eax, test");
		report(pf_count == 1 && test == 45 && save == -1,
		       "write to user stack with AC=0");

		/* This would be trapped by SMEP */
		init_test(i);
		clac();
		asm("jmp 1f + "xstr(USER_BASE)" \n"
		    "1: jmp 2f - "xstr(USER_BASE)" \n"
		    "2:");
		report(pf_count == 0, "executing on user page with AC=0");
	}

	check_smap_nowp();

	// TODO: implicit kernel access from ring 3 (e.g. int)

	return report_summary();
}
