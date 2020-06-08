#include "libcflat.h"
#include "processor.h"
#include "desc.h"

static int test_ud2(bool *rflags_rf)
{
    asm volatile(ASM_TRY("1f")
                 "ud2 \n\t"
                 "1:" :);
    *rflags_rf = exception_rflags_rf();
    return exception_vector();
}

static int test_gp(bool *rflags_rf)
{
    unsigned long tmp;

    asm volatile("mov $0xffffffff, %0 \n\t"
                 ASM_TRY("1f")
		 "mov %0, %%cr4\n\t"
                 "1:"
                 : "=a"(tmp));
    *rflags_rf = exception_rflags_rf();
    return exception_vector();
}

int main(void)
{
    int r;
    bool rflags_rf;

    printf("Starting IDT test\n");
    r = test_gp(&rflags_rf);
    report(r == GP_VECTOR, "Testing #GP");
    report(rflags_rf, "Testing #GP rflags.rf");
    r = test_ud2(&rflags_rf);
    report(r == UD_VECTOR, "Testing #UD");
    report(rflags_rf, "Testing #UD rflags.rf");

    return report_summary();
}
