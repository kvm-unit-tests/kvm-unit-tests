#include "libcflat.h"
#include "desc.h"
#include "processor.h"

#ifdef __x86_64__
#define uint64_t unsigned long
#else
#define uint64_t unsigned long long
#endif

#define XCR_XFEATURE_ENABLED_MASK       0x00000000
#define XCR_XFEATURE_ILLEGAL_MASK       0x00000010

#define XSTATE_FP       0x1
#define XSTATE_SSE      0x2
#define XSTATE_YMM      0x4

static void test_xsave(void)
{
    unsigned long cr4;
    uint64_t supported_xcr0;
    uint64_t test_bits;
    u64 xcr0;

    printf("Legal instruction testing:\n");

    supported_xcr0 = this_cpu_supported_xcr0();
    printf("Supported XCR0 bits: %#lx\n", supported_xcr0);

    test_bits = XSTATE_FP | XSTATE_SSE;
    report((supported_xcr0 & test_bits) == test_bits,
           "Check minimal XSAVE required bits");

    cr4 = read_cr4();
    report(write_cr4_safe(cr4 | X86_CR4_OSXSAVE) == 0, "Set CR4 OSXSAVE");
    report(this_cpu_has(X86_FEATURE_OSXSAVE),
           "Check CPUID.1.ECX.OSXSAVE - expect 1");

    printf("\tLegal tests\n");
    test_bits = XSTATE_FP;
    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == 0,
           "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP)");

    test_bits = XSTATE_FP | XSTATE_SSE;
    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == 0,
           "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP | XSTATE_SSE)");
    report(xgetbv_safe(XCR_XFEATURE_ENABLED_MASK, &xcr0) == 0,
           "        xgetbv(XCR_XFEATURE_ENABLED_MASK)");

    printf("\tIllegal tests\n");
    test_bits = 0;
    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == GP_VECTOR,
           "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, 0) - expect #GP");

    test_bits = XSTATE_SSE;
    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == GP_VECTOR,
           "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_SSE) - expect #GP");

    if (supported_xcr0 & XSTATE_YMM) {
        test_bits = XSTATE_YMM;
        report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == GP_VECTOR,
               "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_YMM) - expect #GP");

        test_bits = XSTATE_FP | XSTATE_YMM;
        report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == GP_VECTOR,
               "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP | XSTATE_YMM) - expect #GP");
    }

    test_bits = XSTATE_SSE;
    report(xsetbv_safe(XCR_XFEATURE_ILLEGAL_MASK, test_bits) == GP_VECTOR,
           "\t\txsetbv(XCR_XFEATURE_ILLEGAL_MASK, XSTATE_FP) - expect #GP");

    test_bits = XSTATE_SSE;
    report(xsetbv_safe(XCR_XFEATURE_ILLEGAL_MASK, test_bits) == GP_VECTOR,
           "\t\txgetbv(XCR_XFEATURE_ILLEGAL_MASK, XSTATE_FP) - expect #GP");

    cr4 &= ~X86_CR4_OSXSAVE;
    report(write_cr4_safe(cr4) == 0, "Unset CR4 OSXSAVE");
    report(this_cpu_has(X86_FEATURE_OSXSAVE) == 0,
           "Check CPUID.1.ECX.OSXSAVE - expect 0");

    printf("\tIllegal tests:\n");
    test_bits = XSTATE_FP;
    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == UD_VECTOR,
           "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP) - expect #UD");

    test_bits = XSTATE_FP | XSTATE_SSE;
    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, test_bits) == UD_VECTOR,
           "\t\txsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP | XSTATE_SSE) - expect #UD");

    printf("\tIllegal tests:\n");
    report(xgetbv_safe(XCR_XFEATURE_ENABLED_MASK, &xcr0) == UD_VECTOR,
           "\txgetbv(XCR_XFEATURE_ENABLED_MASK) - expect #UD");
}

static void test_no_xsave(void)
{
    unsigned long cr4;
    u64 xcr0;

    report(this_cpu_has(X86_FEATURE_OSXSAVE) == 0,
           "Check CPUID.1.ECX.OSXSAVE - expect 0");

    printf("Illegal instruction testing:\n");

    cr4 = read_cr4();
    report(write_cr4_safe(cr4 | X86_CR4_OSXSAVE) == GP_VECTOR,
           "Set OSXSAVE in CR4 - expect #GP");

    report(xgetbv_safe(XCR_XFEATURE_ENABLED_MASK, &xcr0) == UD_VECTOR,
           "Execute xgetbv - expect #UD");

    report(xsetbv_safe(XCR_XFEATURE_ENABLED_MASK, 0x3) == UD_VECTOR,
           "Execute xsetbv - expect #UD");
}

int main(void)
{
    if (this_cpu_has(X86_FEATURE_XSAVE)) {
        printf("CPU has XSAVE feature\n");
        test_xsave();
    } else {
        printf("CPU don't has XSAVE feature\n");
        test_no_xsave();
    }
    return report_summary();
}
