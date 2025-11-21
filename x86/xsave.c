#include "libcflat.h"
#include "desc.h"
#include "processor.h"

#define XSTATE_FP	0x1
#define XSTATE_SSE	0x2
#define XSTATE_YMM	0x4

static void test_unsupported_xcrs(void)
{
	u64 ign;
	int i;

	for (i = 1; i < 64; i++) {
		/* XGETBV(1) returns "XCR0 & XINUSE" on some CPUs. */
		if (i != 1)
			report(xgetbv_safe(i, &ign) == GP_VECTOR,
			       "XGETBV(%u) - expect #GP", i);

		report(xsetbv_safe(i, XSTATE_FP) == GP_VECTOR,
		      "XSETBV(%u, FP) - expect #GP", i);

		report(xsetbv_safe(i, XSTATE_FP | XSTATE_SSE) == GP_VECTOR,
		      "XSETBV(%u, FP|SSE) - expect #GP", i);

		/*
		 * RCX[63:32] are ignored by XGETBV and XSETBV, i.e. testing
		 * bits set above 31 will access XCR0.
		 */
		if (i > 31)
			continue;

		report(xgetbv_safe(BIT(i), &ign) == GP_VECTOR,
		       "XGETBV(0x%lx) - expect #GP", BIT(i));

		report(xsetbv_safe(BIT(i), XSTATE_FP) == GP_VECTOR,
		      "XSETBV(0x%lx, FP) - expect #GP", BIT(i));

		report(xsetbv_safe(BIT(i), XSTATE_FP | XSTATE_SSE) == GP_VECTOR,
		      "XSETBV(0x%lx, FP|SSE) - expect #GP", BIT(i));
	}
}

static void test_xsave(void)
{
	u64 supported_xcr0, test_bits;
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

	test_unsupported_xcrs();

	write_cr4(cr4);

	report(this_cpu_has(X86_FEATURE_OSXSAVE) == !!(cr4 & X86_CR4_OSXSAVE),
	       "CPUID.1.ECX.OSXSAVE == CR4.OSXSAVE");
}

static void test_no_xsave(void)
{
	unsigned long cr4 = read_cr4();
	u64 xcr0;

	if (cr4 & X86_CR4_OSXSAVE)
		write_cr4(cr4 & ~X86_CR4_OSXSAVE);

	report(this_cpu_has(X86_FEATURE_OSXSAVE) == 0,
	       "Check CPUID.1.ECX.OSXSAVE - expect 0");

	report(read_xcr0_safe(&xcr0) == UD_VECTOR,
	       "Read XCR0 without OSXSAVE enabled - expect #UD");

	report(write_xcr0_safe(XSTATE_FP | XSTATE_SSE) == UD_VECTOR,
	       "Write XCR0=(FP|SSE) without XSAVE support - expect #UD");

	if (cr4 & X86_CR4_OSXSAVE)
		write_cr4(cr4);
}

int main(void)
{
	test_no_xsave();

	if (this_cpu_has(X86_FEATURE_XSAVE)) {
		test_xsave();
	} else {
		report_skip("XSAVE unsupported, skipping positive tests");

		report(write_cr4_safe(read_cr4() | X86_CR4_OSXSAVE) == GP_VECTOR,
		       "Set CR4.OSXSAVE without XSAVE- expect #GP");
	}

	return report_summary();
}
