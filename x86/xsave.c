#include "libcflat.h"
#include "desc.h"
#include "processor.h"

#define XCR_XFEATURE_ILLEGAL_MASK	0x00000010

#define XSTATE_FP	0x1
#define XSTATE_SSE	0x2
#define XSTATE_YMM	0x4

static void test_xsave(void)
{
	u64 supported_xcr0, xcr0, test_bits;
	unsigned long cr4;

	printf("Legal instruction testing:\n");

	supported_xcr0 = this_cpu_supported_xcr0();
	printf("Supported XCR0 bits: %#lx\n", supported_xcr0);

	test_bits = XSTATE_FP | XSTATE_SSE;
	report((supported_xcr0 & test_bits) == test_bits,
	       "Check minimal XSAVE required bits");

	cr4 = read_cr4();
	write_cr4(cr4 | X86_CR4_OSXSAVE);

	report(this_cpu_has(X86_FEATURE_OSXSAVE),
	       "Check CPUID.1.ECX.OSXSAVE - expect 1");

	printf("\tLegal tests\n");
	write_xcr0(XSTATE_FP);
	write_xcr0(XSTATE_FP | XSTATE_SSE);
	(void)read_xcr0();

	printf("\tIllegal tests\n");
	report(write_xcr0_safe(0) == GP_VECTOR,
	       "\t\tWrite XCR0 = 0 - expect #GP");

	report(write_xcr0_safe(XSTATE_SSE) == GP_VECTOR,
	       "\t\tWrite XCR0 = SSE - expect #GP");

	if (supported_xcr0 & XSTATE_YMM) {
		report(write_xcr0_safe(XSTATE_YMM) == GP_VECTOR,
		       "\t\tWrite XCR0 = YMM - expect #GP");

		report(write_xcr0_safe(XSTATE_FP | XSTATE_YMM) == GP_VECTOR,
		       "\t\tWrite XCR0 = (FP | YMM) - expect #GP");
	}

	test_bits = XSTATE_SSE;
	report(xsetbv_safe(XCR_XFEATURE_ILLEGAL_MASK, test_bits) == GP_VECTOR,
	       "\t\txsetbv(XCR_XFEATURE_ILLEGAL_MASK, XSTATE_FP) - expect #GP");

	test_bits = XSTATE_SSE;
	report(xsetbv_safe(XCR_XFEATURE_ILLEGAL_MASK, test_bits) == GP_VECTOR,
	       "\t\txgetbv(XCR_XFEATURE_ILLEGAL_MASK, XSTATE_FP) - expect #GP");

	write_cr4(cr4 & ~X86_CR4_OSXSAVE);
	report(this_cpu_has(X86_FEATURE_OSXSAVE) == 0,
	       "Check CPUID.1.ECX.OSXSAVE - expect 0");

	printf("\tIllegal tests:\n");
	report(write_xcr0_safe(XSTATE_FP) == UD_VECTOR,
	       "\t\tWrite XCR0=FP with CR4.OSXSAVE=0 - expect #UD");

	report(write_xcr0_safe(XSTATE_FP | XSTATE_SSE) == UD_VECTOR,
	       "\t\tWrite XCR0=(FP|SSE) with CR4.OSXSAVE=0 - expect #UD");

	printf("\tIllegal tests:\n");
	report(read_xcr0_safe(&xcr0) == UD_VECTOR,
	       "\tRead XCR0 with CR4.OSXSAVE=0 - expect #UD");
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

	report(read_xcr0_safe(&xcr0) == UD_VECTOR,
	       "Read XCR0 without XSAVE support - expect #UD");

	report(write_xcr0_safe(XSTATE_FP | XSTATE_SSE) == UD_VECTOR,
	       "Write XCR0=(FP|SSE) without XSAVE support - expect #UD");
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
