/* msr tests */

#include "libcflat.h"
#include "processor.h"
#include "msr.h"

struct msr_info {
	int index;
	const char *name;
	struct tc {
		int valid;
		unsigned long long value;
		unsigned long long expected;
	} val_pairs[20];
};


#define addr_64 0x0000123456789abcULL
#define addr_ul (unsigned long)addr_64

struct msr_info msr_info[] =
{
	{ .index = MSR_IA32_SYSENTER_CS, .name = "MSR_IA32_SYSENTER_CS",
	  .val_pairs = {{ .valid = 1, .value = 0x1234, .expected = 0x1234}}
	},
	{ .index = MSR_IA32_SYSENTER_ESP, .name = "MSR_IA32_SYSENTER_ESP",
	  .val_pairs = {{ .valid = 1, .value = addr_ul, .expected = addr_ul}}
	},
	{ .index = MSR_IA32_SYSENTER_EIP, .name = "MSR_IA32_SYSENTER_EIP",
	  .val_pairs = {{ .valid = 1, .value = addr_ul, .expected = addr_ul}}
	},
	{ .index = MSR_IA32_MISC_ENABLE, .name = "MSR_IA32_MISC_ENABLE",
	  // reserved: 1:2, 4:6, 8:10, 13:15, 17, 19:21, 24:33, 35:63
	  .val_pairs = {{ .valid = 1, .value = 0x400c51889, .expected = 0x400c51889}}
	},
	{ .index = MSR_IA32_CR_PAT, .name = "MSR_IA32_CR_PAT",
	  .val_pairs = {{ .valid = 1, .value = 0x07070707, .expected = 0x07070707}}
	},
#ifdef __x86_64__
	{ .index = MSR_FS_BASE, .name = "MSR_FS_BASE",
	  .val_pairs = {{ .valid = 1, .value = addr_64, .expected = addr_64}}
	},
	{ .index = MSR_GS_BASE, .name = "MSR_GS_BASE",
	  .val_pairs = {{ .valid = 1, .value = addr_64, .expected = addr_64}}
	},
	{ .index = MSR_KERNEL_GS_BASE, .name = "MSR_KERNEL_GS_BASE",
	  .val_pairs = {{ .valid = 1, .value = addr_64, .expected = addr_64}}
	},
	{ .index = MSR_EFER, .name = "MSR_EFER",
	  .val_pairs = {{ .valid = 1, .value = 0xD00, .expected = 0xD00}}
	},
	{ .index = MSR_LSTAR, .name = "MSR_LSTAR",
	  .val_pairs = {{ .valid = 1, .value = addr_64, .expected = addr_64}}
	},
	{ .index = MSR_CSTAR, .name = "MSR_CSTAR",
	  .val_pairs = {{ .valid = 1, .value = addr_64, .expected = addr_64}}
	},
	{ .index = MSR_SYSCALL_MASK, .name = "MSR_SYSCALL_MASK",
	  .val_pairs = {{ .valid = 1, .value = 0xffffffff, .expected = 0xffffffff}}
	},
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

static void test_msr_rw(int msr_index, unsigned long long input, unsigned long long expected)
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
	wrmsr(msr_index, input);
	r = rdmsr(msr_index);
	wrmsr(msr_index, orig);
	if (expected != r) {
		printf("testing %s: output = %#" PRIx32 ":%#" PRIx32
		       " expected = %#" PRIx32 ":%#" PRIx32 "\n", sptr,
		       (u32)(r >> 32), (u32)r, (u32)(expected >> 32), (u32)expected);
	}
	report(expected == r, "%s", sptr);
}

int main(int ac, char **av)
{
	int i, j;
	for (i = 0 ; i < ARRAY_SIZE(msr_info); i++) {
		for (j = 0; j < ARRAY_SIZE(msr_info[i].val_pairs); j++) {
			if (msr_info[i].val_pairs[j].valid) {
				test_msr_rw(msr_info[i].index, msr_info[i].val_pairs[j].value, msr_info[i].val_pairs[j].expected);
			} else {
				break;
			}
		}
	}

	return report_summary();
}
