/* msr tests */

#include "libcflat.h"
#include "processor.h"
#include "msr.h"

struct msr_info {
	int index;
	const char *name;
	unsigned long long value;
};


#define addr_64 0x0000123456789abcULL
#define addr_ul (unsigned long)addr_64

#define MSR_TEST(msr, val)	\
	{ .index = msr, .name = #msr, .value = val }

struct msr_info msr_info[] =
{
	MSR_TEST(MSR_IA32_SYSENTER_CS, 0x1234),
	MSR_TEST(MSR_IA32_SYSENTER_ESP, addr_ul),
	MSR_TEST(MSR_IA32_SYSENTER_EIP, addr_ul),
	// reserved: 1:2, 4:6, 8:10, 13:15, 17, 19:21, 24:33, 35:63
	MSR_TEST(MSR_IA32_MISC_ENABLE, 0x400c51889),
	MSR_TEST(MSR_IA32_CR_PAT, 0x07070707),
#ifdef __x86_64__
	MSR_TEST(MSR_FS_BASE, addr_64),
	MSR_TEST(MSR_GS_BASE, addr_64),
	MSR_TEST(MSR_KERNEL_GS_BASE, addr_64),
	MSR_TEST(MSR_EFER, 0xD00),
	MSR_TEST(MSR_LSTAR, addr_64),
	MSR_TEST(MSR_CSTAR, addr_64),
	MSR_TEST(MSR_SYSCALL_MASK, 0xffffffff),
#endif
//	MSR_IA32_DEBUGCTLMSR needs svm feature LBRV
//	MSR_VM_HSAVE_PA only AMD host
};

static int find_msr_info(int msr_index)
{
	int i;

	for (i = 0; i < sizeof(msr_info)/sizeof(msr_info[0]) ; i++) {
		if (msr_info[i].index == msr_index)
			return i;
	}
	return -1;
}

static void test_msr_rw(int msr_index, unsigned long long val)
{
	unsigned long long r, orig;
	int index;
	const char *sptr;

	if ((index = find_msr_info(msr_index)) != -1) {
		sptr = msr_info[index].name;
	} else {
		printf("couldn't find name for msr # %#x, skipping\n", msr_index);
		return;
	}

	orig = rdmsr(msr_index);
	wrmsr(msr_index, val);
	r = rdmsr(msr_index);
	wrmsr(msr_index, orig);
	if (r != val) {
		printf("testing %s: output = %#" PRIx32 ":%#" PRIx32
		       " expected = %#" PRIx32 ":%#" PRIx32 "\n", sptr,
		       (u32)(r >> 32), (u32)r, (u32)(val >> 32), (u32)val);
	}
	report(val == r, "%s", sptr);
}

int main(int ac, char **av)
{
	int i;

	for (i = 0 ; i < ARRAY_SIZE(msr_info); i++)
		test_msr_rw(msr_info[i].index, msr_info[i].value);

	return report_summary();
}
