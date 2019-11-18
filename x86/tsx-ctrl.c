/* TSX tests */

#include "libcflat.h"
#include "processor.h"
#include "msr.h"

static bool try_transaction(void)
{
    unsigned x;
    int i;

    for (i = 0; i < 100; i++) {
        x = 0;
        /*
         * The value before the transaction is important, so make the
         * operand input/output.
         */
        asm volatile("xbegin 2f; movb $1, %0; xend; 2:" : "+m" (x) : : "eax");
        if (x) {
            return true;
        }
    }
    return false;
}

int main(int ac, char **av)
{
    if (!this_cpu_has(X86_FEATURE_RTM)) {
        report_skip("TSX not available");
	return 0;
    }
    if (!this_cpu_has(X86_FEATURE_ARCH_CAPABILITIES)) {
        report_skip("ARCH_CAPABILITIES not available");
	return 0;
    }
    if (!(rdmsr(MSR_IA32_ARCH_CAPABILITIES) & ARCH_CAP_TSX_CTRL_MSR)) {
        report_skip("TSX_CTRL not available");
	return 0;
    }

    report("TSX_CTRL should be 0", rdmsr(MSR_IA32_TSX_CTRL) == 0);
    report("Transactions do not abort", try_transaction());

    wrmsr(MSR_IA32_TSX_CTRL, TSX_CTRL_CPUID_CLEAR);
    report("TSX_CTRL hides RTM", !this_cpu_has(X86_FEATURE_RTM));
    report("TSX_CTRL hides HLE", !this_cpu_has(X86_FEATURE_HLE));

    /* Microcode might hide HLE unconditionally */
    wrmsr(MSR_IA32_TSX_CTRL, 0);
    report("TSX_CTRL=0 unhides RTM", this_cpu_has(X86_FEATURE_RTM));

    wrmsr(MSR_IA32_TSX_CTRL, TSX_CTRL_RTM_DISABLE);
    report("TSX_CTRL causes transactions to abort", !try_transaction());

    wrmsr(MSR_IA32_TSX_CTRL, 0);
    report("TSX_CTRL=0 causes transactions to succeed", try_transaction());

    return report_summary();
}

