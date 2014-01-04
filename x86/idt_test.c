#include "libcflat.h"
#include "desc.h"

int test_ud2(void)
{
    asm volatile(ASM_TRY("1f")
                 "ud2 \n\t"
                 "1:" :);
    return exception_vector();
}

int test_gp(void)
{
    unsigned long tmp;

    asm volatile("mov $0xffffffff, %0 \n\t"
                 ASM_TRY("1f")
		 "mov %0, %%cr4\n\t"
                 "1:"
                 : "=a"(tmp));
    return exception_vector();
}

int main(void)
{
    int r;

    printf("Starting IDT test\n");
    setup_idt();
    r = test_gp();
    report("Testing #GP", r == GP_VECTOR);
    r = test_ud2();
    report("Testing #UD", r == UD_VECTOR);

    return report_summary();
}
