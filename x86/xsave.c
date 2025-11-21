#include "libcflat.h"
#include "desc.h"
#include "processor.h"

char __attribute__((aligned(32))) v32_1[32];
char __attribute__((aligned(32))) v32_2[32];
char __attribute__((aligned(32))) v32_3[32];

static void initialize_avx_buffers(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(v32_1); i++)
		v32_1[i] = (char)rdtsc();

	memset(v32_2, 0, sizeof(v32_2));
	memset(v32_3, 0, sizeof(v32_3));
}

#define __TEST_VMOVDQA(reg1, reg2, FEP)					\
do {									\
	asm volatile(FEP "vmovdqa v32_1(%%rip), %%" #reg1 "\n"		\
		     FEP "vmovdqa %%" #reg1 ", %%" #reg2 "\n"		\
		     FEP "vmovdqa %%" #reg2 ", v32_2(%%rip)\n"		\
		     "vmovdqa %%" #reg2 ", v32_3(%%rip)\n"		\
		     ::: "memory", #reg1, #reg2);			\
									\
	report(!memcmp(v32_1, v32_2, sizeof(v32_1)),			\
	       "%s VMOVDQA using " #reg1 " and " #reg2,			\
	       strlen(FEP) ? "Emulated" : "Native");			\
	report(!memcmp(v32_1, v32_3, sizeof(v32_1)),			\
	       "%s VMOVDQA using " #reg1 " and " #reg2,			\
	       strlen(FEP) ? "Emulated+Native" : "Native");		\
} while (0)

#define TEST_VMOVDQA(r1, r2)						\
do {									\
	initialize_avx_buffers();					\
									\
	__TEST_VMOVDQA(ymm##r1, ymm##r2, "");				\
									\
	if (is_fep_available)						\
		__TEST_VMOVDQA(ymm##r1, ymm##r2, KVM_FEP);		\
} while (0)

static void test_write_xcr0(u64 val)
{
	write_xcr0(val);

	report(read_xcr0() == val,
	       "Wanted XCR0 == 0x%lx, got XCR0 == 0x%lx", val, read_xcr0());
}

static __attribute__((target("avx"))) void test_avx_vmovdqa(void)
{
	test_write_xcr0(XFEATURE_MASK_FP_SSE | XFEATURE_MASK_YMM);

	TEST_VMOVDQA(0, 15);
	TEST_VMOVDQA(1, 14);
	TEST_VMOVDQA(2, 13);
	TEST_VMOVDQA(3, 12);
	TEST_VMOVDQA(4, 11);
	TEST_VMOVDQA(5, 10);
	TEST_VMOVDQA(6, 9);
	TEST_VMOVDQA(7, 8);
	TEST_VMOVDQA(8, 7);
	TEST_VMOVDQA(9, 6);
	TEST_VMOVDQA(10, 5);
	TEST_VMOVDQA(11, 4);
	TEST_VMOVDQA(12, 3);
	TEST_VMOVDQA(13, 2);
	TEST_VMOVDQA(14, 2);
	TEST_VMOVDQA(15, 1);
}

static void test_unsupported_xcrs(void)
{
	u64 ign;
	int i;

	for (i = 1; i < 64; i++) {
		/* XGETBV(1) returns "XCR0 & XINUSE" on some CPUs. */
		if (i != 1)
			report(xgetbv_safe(i, &ign) == GP_VECTOR,
			       "XGETBV(%u) - expect #GP", i);

		report(xsetbv_safe(i, XFEATURE_MASK_FP) == GP_VECTOR,
		      "XSETBV(%u, FP) - expect #GP", i);

		report(xsetbv_safe(i, XFEATURE_MASK_FP_SSE) == GP_VECTOR,
		      "XSETBV(%u, FP|SSE) - expect #GP", i);

		/*
		 * RCX[63:32] are ignored by XGETBV and XSETBV, i.e. testing
		 * bits set above 31 will access XCR0.
		 */
		if (i > 31)
			continue;

		report(xgetbv_safe(BIT(i), &ign) == GP_VECTOR,
		       "XGETBV(0x%lx) - expect #GP", BIT(i));

		report(xsetbv_safe(BIT(i), XFEATURE_MASK_FP) == GP_VECTOR,
		      "XSETBV(0x%lx, FP) - expect #GP", BIT(i));

		report(xsetbv_safe(BIT(i), XFEATURE_MASK_FP_SSE) == GP_VECTOR,
		      "XSETBV(0x%lx, FP|SSE) - expect #GP", BIT(i));
	}
}

static void test_xsave(void)
{
	u64 supported_xcr0;
	unsigned long cr4;

	supported_xcr0 = this_cpu_supported_xcr0();
	printf("Supported XCR0 bits: %#lx\n", supported_xcr0);

	report((supported_xcr0 & XFEATURE_MASK_FP_SSE) == XFEATURE_MASK_FP_SSE,
	       "FP and SSE should always be supported in XCR0");

	cr4 = read_cr4();
	write_cr4(cr4 | X86_CR4_OSXSAVE);

	report(this_cpu_has(X86_FEATURE_OSXSAVE),
	       "Check CPUID.1.ECX.OSXSAVE - expect 1");

	test_write_xcr0(XFEATURE_MASK_FP);
	test_write_xcr0(XFEATURE_MASK_FP_SSE);

	if (supported_xcr0 & XFEATURE_MASK_YMM)
		test_avx_vmovdqa();

	report(write_xcr0_safe(0) == GP_VECTOR,
	       "Write XCR0 = 0 - expect #GP");

	report(write_xcr0_safe(XFEATURE_MASK_SSE) == GP_VECTOR,
	       "Write XCR0 = SSE - expect #GP");

	if (supported_xcr0 & XFEATURE_MASK_YMM) {
		report(write_xcr0_safe(XFEATURE_MASK_YMM) == GP_VECTOR,
		       "Write XCR0 = YMM - expect #GP");

		report(write_xcr0_safe(XFEATURE_MASK_FP | XFEATURE_MASK_YMM) == GP_VECTOR,
		       "Write XCR0 = (FP | YMM) - expect #GP");
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

	report(write_xcr0_safe(XFEATURE_MASK_FP_SSE) == UD_VECTOR,
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
