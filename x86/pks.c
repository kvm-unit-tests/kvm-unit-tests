#include "libcflat.h"
#include <alloc_page.h>
#include "x86/desc.h"
#include "x86/processor.h"
#include "x86/vm.h"
#include "x86/msr.h"

#define PTE_PKEY_BIT     59
#define SUPER_BASE        (1 << 23)
#define SUPER_VAR(v)      (*((__typeof__(&(v))) (((unsigned long)&v) + SUPER_BASE)))

volatile int pf_count = 0;
volatile unsigned save;
volatile unsigned test;

static void set_cr0_wp(int wp)
{
    unsigned long cr0 = read_cr0();

    cr0 &= ~X86_CR0_WP;
    if (wp)
        cr0 |= X86_CR0_WP;
    write_cr0(cr0);
}

void do_pf_tss(unsigned long error_code);
void do_pf_tss(unsigned long error_code)
{
    printf("#PF handler, error code: 0x%lx\n", error_code);
    pf_count++;
    save = test;
    wrmsr(MSR_IA32_PKRS, 0);
}

extern void pf_tss(void);

asm ("pf_tss: \n\t"
#ifdef __x86_64__
    // no task on x86_64, save/restore caller-save regs
    "push %rax; push %rcx; push %rdx; push %rsi; push %rdi\n"
    "push %r8; push %r9; push %r10; push %r11\n"
    "mov 9*8(%rsp), %rdi\n"
#endif
    "call do_pf_tss \n\t"
#ifdef __x86_64__
    "pop %r11; pop %r10; pop %r9; pop %r8\n"
    "pop %rdi; pop %rsi; pop %rdx; pop %rcx; pop %rax\n"
#endif
    "add $"S", %"R "sp\n\t" // discard error code
    "iret"W" \n\t"
    "jmp pf_tss\n\t"
    );

static void init_test(void)
{
    pf_count = 0;

    invlpg(&test);
    invlpg(&SUPER_VAR(test));
    wrmsr(MSR_IA32_PKRS, 0);
    set_cr0_wp(0);
}

int main(int ac, char **av)
{
    unsigned long i;
    unsigned int pkey = 0x2;
    unsigned int pkrs_ad = 0x10;
    unsigned int pkrs_wd = 0x20;

    if (!this_cpu_has(X86_FEATURE_PKS)) {
        printf("PKS not enabled\n");
        return report_summary();
    }

    setup_vm();
    setup_alt_stack();
    set_intr_alt_stack(14, pf_tss);

    if (reserve_pages(SUPER_BASE, SUPER_BASE >> 12))
        report_abort("Could not reserve memory");

    for (i = 0; i < SUPER_BASE; i += PAGE_SIZE) {
        *get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) |= ((unsigned long)pkey << PTE_PKEY_BIT);
        invlpg((void *)i);
    }

    // Present the same 16MB as supervisor pages in the 16MB-32MB range
    for (i = SUPER_BASE; i < 2 * SUPER_BASE; i += PAGE_SIZE) {
        *get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) &= ~SUPER_BASE;
        *get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) &= ~PT_USER_MASK;
        *get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) |= ((unsigned long)pkey << PTE_PKEY_BIT);
        invlpg((void *)i);
    }

    write_cr4(read_cr4() | X86_CR4_PKS);
    write_cr3(read_cr3());

    init_test();
    set_cr0_wp(1);
    wrmsr(MSR_IA32_PKRS, pkrs_ad);
    SUPER_VAR(test) = 21;
    report(pf_count == 1 && test == 21 && save == 0,
           "write to supervisor page when pkrs is ad and wp == 1");

    init_test();
    set_cr0_wp(0);
    wrmsr(MSR_IA32_PKRS, pkrs_ad);
    SUPER_VAR(test) = 22;
    report(pf_count == 1 && test == 22 && save == 21,
           "write to supervisor page when pkrs is ad and wp == 0");

    init_test();
    set_cr0_wp(1);
    wrmsr(MSR_IA32_PKRS, pkrs_wd);
    SUPER_VAR(test) = 23;
    report(pf_count == 1 && test == 23 && save == 22,
           "write to supervisor page when pkrs is wd and wp == 1");

    init_test();
    set_cr0_wp(0);
    wrmsr(MSR_IA32_PKRS, pkrs_wd);
    SUPER_VAR(test) = 24;
    report(pf_count == 0 && test == 24,
           "write to supervisor page when pkrs is wd and wp == 0");

    init_test();
    set_cr0_wp(0);
    wrmsr(MSR_IA32_PKRS, pkrs_wd);
    test = 25;
    report(pf_count == 0 && test == 25,
           "write to user page when pkrs is wd and wp == 0");

    init_test();
    set_cr0_wp(1);
    wrmsr(MSR_IA32_PKRS, pkrs_wd);
    test = 26;
    report(pf_count == 0 && test == 26,
           "write to user page when pkrs is wd and wp == 1");

    init_test();
    wrmsr(MSR_IA32_PKRS, pkrs_ad);
    (void)((__typeof__(&(test))) (((unsigned long)&test)));
    report(pf_count == 0, "read from user page when pkrs is ad");

    return report_summary();
}
