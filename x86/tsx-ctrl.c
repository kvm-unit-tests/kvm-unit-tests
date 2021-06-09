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
	return report_summary();
    }
    if (!this_cpu_has(X86_FEATURE_ARCH_CAPABILITIES)) {
        report_skip("ARCH_CAPABILITIES not available");
	return report_summary();
    }
    if (!(rdmsr(MSR_IA32_ARCH_CAPABILITIES) & ARCH_CAP_TSX_CTRL_MSR)) {
        report_skip("TSX_CTRL not available");
	return report_summary();
    }

    report(rdmsr(MSR_IA32_TSX_CTRL) == 0, "TSX_CTRL should be 0");
    report(try_transaction(), "Transactions do not abort");

    wrmsr(MSR_IA32_TSX_CTRL, TSX_CTRL_CPUID_CLEAR);
    report(!this_cpu_has(X86_FEATURE_RTM), "TSX_CTRL hides RTM");
    report(!this_cpu_has(X86_FEATURE_HLE), "TSX_CTRL hides HLE");

    /* Microcode might hide HLE unconditionally */
    wrmsr(MSR_IA32_TSX_CTRL, 0);
    report(this_cpu_has(X86_FEATURE_RTM), "TSX_CTRL=0 unhides RTM");

    wrmsr(MSR_IA32_TSX_CTRL, TSX_CTRL_RTM_DISABLE);
    report(!try_transaction(), "TSX_CTRL causes transactions to abort");

    wrmsr(MSR_IA32_TSX_CTRL, 0);
    report(try_transaction(), "TSX_CTRL=0 causes transactions to succeed");

    return report_summary();
}

