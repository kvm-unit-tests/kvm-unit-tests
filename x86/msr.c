/* msr tests */

#include "libcflat.h"
#include "processor.h"
#include "msr.h"
#include <stdlib.h>

/**
 * This test allows two modes:
 * 1. Default: the `msr_info' array contains the default test configurations
 * 2. Custom: by providing command line arguments it is possible to test any MSR and value
 *	Parameters order:
 *		1. msr index as a base 16 number
 *		2. value as a base 16 number
 */

struct msr_info {
	int index;
	bool is_64bit_only;
	const char *name;
	unsigned long long value;
	unsigned long long keep;
};


#define addr_64 0x0000123456789abcULL
#define addr_ul (unsigned long)addr_64

#define MSR_TEST(msr, val, ro)	\
	{ .index = msr, .name = #msr, .value = val, .is_64bit_only = false, .keep = ro }
#define MSR_TEST_ONLY64(msr, val, ro)	\
	{ .index = msr, .name = #msr, .value = val, .is_64bit_only = true, .keep = ro }

struct msr_info msr_info[] =
{
	MSR_TEST(MSR_IA32_SYSENTER_CS, 0x1234, 0),
	MSR_TEST(MSR_IA32_SYSENTER_ESP, addr_ul, 0),
	MSR_TEST(MSR_IA32_SYSENTER_EIP, addr_ul, 0),
	// reserved: 1:2, 4:6, 8:10, 13:15, 17, 19:21, 24:33, 35:63
	// read-only: 7, 11, 12
	MSR_TEST(MSR_IA32_MISC_ENABLE, 0x400c50809, 0x1880),
	MSR_TEST(MSR_IA32_CR_PAT, 0x07070707, 0),
	MSR_TEST_ONLY64(MSR_FS_BASE, addr_64, 0),
	MSR_TEST_ONLY64(MSR_GS_BASE, addr_64, 0),
	MSR_TEST_ONLY64(MSR_KERNEL_GS_BASE, addr_64, 0),
	MSR_TEST(MSR_EFER, EFER_SCE, 0),
	MSR_TEST_ONLY64(MSR_LSTAR, addr_64, 0),
	MSR_TEST_ONLY64(MSR_CSTAR, addr_64, 0),
	MSR_TEST_ONLY64(MSR_SYSCALL_MASK, 0xffffffff, 0),
//	MSR_IA32_DEBUGCTLMSR needs svm feature LBRV
//	MSR_VM_HSAVE_PA only AMD host
};

static void __test_msr_rw(u32 msr, const char *name, unsigned long long val,
			  unsigned long long keep_mask)
{
	unsigned long long r, orig;

	orig = rdmsr(msr);
	/*
	 * Special case EFER since clearing LME/LMA is not allowed in 64-bit mode,
	 * and conversely setting those bits on 32-bit CPUs is not allowed.  Treat
	 * the desired value as extra bits to set.
	 */
	if (msr == MSR_EFER)
		val |= orig;
	else
		val = (val & ~keep_mask) | (orig & keep_mask);

	wrmsr(msr, val);
	r = rdmsr(msr);
	wrmsr(msr, orig);

	if (r != val) {
		printf("testing %s: output = %#" PRIx32 ":%#" PRIx32
		       " expected = %#" PRIx32 ":%#" PRIx32 "\n", name,
		       (u32)(r >> 32), (u32)r, (u32)(val >> 32), (u32)val);
	}
	report(val == r, "%s", name);
}

static void test_msr_rw(u32 msr, const char *name, unsigned long long val)
{
	__test_msr_rw(msr, name, val, 0);
}

static void test_wrmsr_fault(u32 msr, const char *name, unsigned long long val)
{
	unsigned char vector = wrmsr_safe(msr, val);

	report(vector == GP_VECTOR,
	       "Expected #GP on WRSMR(%s, 0x%llx), got vector %d",
	       name, val, vector);
}

static void test_rdmsr_fault(u32 msr, const char *name)
{
	uint64_t ignored;
	unsigned char vector = rdmsr_safe(msr, &ignored);

	report(vector == GP_VECTOR,
	       "Expected #GP on RDSMR(%s), got vector %d", name, vector);
}

static void test_msr(struct msr_info *msr, bool is_64bit_host)
{
	if (is_64bit_host || !msr->is_64bit_only) {
		__test_msr_rw(msr->index, msr->name, msr->value, msr->keep);

		/*
		 * The 64-bit only MSRs that take an address always perform
		 * canonical checks on both Intel and AMD.
		 */
		if (msr->is_64bit_only &&
		    msr->value == addr_64)
			test_wrmsr_fault(msr->index, msr->name, NONCANONICAL);
	} else {
		test_wrmsr_fault(msr->index, msr->name, msr->value);
		test_rdmsr_fault(msr->index, msr->name);
	}
}

static void test_custom_msr(int ac, char **av)
{
	bool is_64bit_host = this_cpu_has(X86_FEATURE_LM);
	char msr_name[32];
	int index = strtoul(av[1], NULL, 0x10);
	snprintf(msr_name, sizeof(msr_name), "MSR:0x%x", index);

	struct msr_info msr = {
		.index = index,
		.name = msr_name,
		.value = strtoull(av[2], NULL, 0x10)
	};
	test_msr(&msr, is_64bit_host);
}

static void test_misc_msrs(void)
{
	bool is_64bit_host = this_cpu_has(X86_FEATURE_LM);
	int i;

	for (i = 0 ; i < ARRAY_SIZE(msr_info); i++)
		test_msr(&msr_info[i], is_64bit_host);
}

static void test_mce_msrs(void)
{
	bool is_64bit_host = this_cpu_has(X86_FEATURE_LM);
	unsigned int nr_mce_banks;
	char msr_name[32];
	int i;

	nr_mce_banks = rdmsr(MSR_IA32_MCG_CAP) & 0xff;
	for (i = 0; i < nr_mce_banks; i++) {
		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_CTL", i);
		test_msr_rw(MSR_IA32_MCx_CTL(i), msr_name, 0);
		test_msr_rw(MSR_IA32_MCx_CTL(i), msr_name, -1ull);
		test_wrmsr_fault(MSR_IA32_MCx_CTL(i), msr_name, NONCANONICAL);

		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_STATUS", i);
		test_msr_rw(MSR_IA32_MCx_STATUS(i), msr_name, 0);
		/*
		 * STATUS MSRs can only be written with '0' (to clear the MSR),
		 * except on AMD-based systems with bit 18 set in MSR_K7_HWCR.
		 * That bit is not architectural and should not be set by
		 * default by KVM or by the VMM (though this might fail if run
		 * on bare metal).
		 */
		test_wrmsr_fault(MSR_IA32_MCx_STATUS(i), msr_name, 1);

		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_ADDR", i);
		test_msr_rw(MSR_IA32_MCx_ADDR(i), msr_name, 0);
		test_msr_rw(MSR_IA32_MCx_ADDR(i), msr_name, -1ull);
		/*
		 * The ADDR is a physical address, and all bits are writable on
		 * 64-bit hosts.  Don't test the negative case, as KVM doesn't
		 * enforce checks on bits 63:36 for 32-bit hosts.  The behavior
		 * depends on the underlying hardware, e.g. a 32-bit guest on a
		 * 64-bit host may observe 64-bit values in the ADDR MSRs.
		 */
		if (is_64bit_host)
			test_msr_rw(MSR_IA32_MCx_ADDR(i), msr_name, NONCANONICAL);

		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_MISC", i);
		test_msr_rw(MSR_IA32_MCx_MISC(i), msr_name, 0);
		test_msr_rw(MSR_IA32_MCx_MISC(i), msr_name, -1ull);
		test_msr_rw(MSR_IA32_MCx_MISC(i), msr_name, NONCANONICAL);
	}

	/*
	 * The theoretical maximum number of MCE banks is 32 (on Intel CPUs,
	 * without jumping to a new base address), as the last unclaimed MSR is
	 * 0x479; 0x480 begins the VMX MSRs.  Verify accesses to theoretically
	 * legal, unsupported MSRs fault.
	 */
	for (i = nr_mce_banks; i < 32; i++) {
		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_CTL", i);
		test_rdmsr_fault(MSR_IA32_MCx_CTL(i), msr_name);
		test_wrmsr_fault(MSR_IA32_MCx_CTL(i), msr_name, 0);

		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_STATUS", i);
		test_rdmsr_fault(MSR_IA32_MCx_STATUS(i), msr_name);
		test_wrmsr_fault(MSR_IA32_MCx_STATUS(i), msr_name, 0);

		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_ADDR", i);
		test_rdmsr_fault(MSR_IA32_MCx_ADDR(i), msr_name);
		test_wrmsr_fault(MSR_IA32_MCx_ADDR(i), msr_name, 0);

		snprintf(msr_name, sizeof(msr_name), "MSR_IA32_MC%u_MISC", i);
		test_rdmsr_fault(MSR_IA32_MCx_MISC(i), msr_name);
		test_wrmsr_fault(MSR_IA32_MCx_MISC(i), msr_name, 0);
	}
}

int main(int ac, char **av)
{
	/*
	 * If the user provided an MSR+value, test exactly that and skip all
	 * built-in testcases.
	 */
	if (ac == 3) {
		test_custom_msr(ac, av);
	} else {
		test_misc_msrs();
		test_mce_msrs();
	}

	return report_summary();
}
