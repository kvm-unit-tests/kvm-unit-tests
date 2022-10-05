#ifndef _X86_PROCESSOR_H_
#define _X86_PROCESSOR_H_

#include "libcflat.h"
#include "desc.h"
#include "msr.h"
#include <bitops.h>
#include <stdint.h>

#define NONCANONICAL	0xaaaaaaaaaaaaaaaaull

#ifdef __x86_64__
#  define R "r"
#  define W "q"
#  define S "8"
#else
#  define R "e"
#  define W "l"
#  define S "4"
#endif

#define DB_VECTOR 1
#define BP_VECTOR 3
#define UD_VECTOR 6
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define AC_VECTOR 17
#define CP_VECTOR 21

#define X86_CR0_PE_BIT		(0)
#define X86_CR0_PE		BIT(X86_CR0_PE_BIT)
#define X86_CR0_MP_BIT		(1)
#define X86_CR0_MP		BIT(X86_CR0_MP_BIT)
#define X86_CR0_EM_BIT		(2)
#define X86_CR0_EM		BIT(X86_CR0_EM_BIT)
#define X86_CR0_TS_BIT		(3)
#define X86_CR0_TS		BIT(X86_CR0_TS_BIT)
#define X86_CR0_ET_BIT		(4)
#define X86_CR0_ET		BIT(X86_CR0_ET_BIT)
#define X86_CR0_NE_BIT		(5)
#define X86_CR0_NE		BIT(X86_CR0_NE_BIT)
#define X86_CR0_WP_BIT		(16)
#define X86_CR0_WP		BIT(X86_CR0_WP_BIT)
#define X86_CR0_AM_BIT		(18)
#define X86_CR0_AM		BIT(X86_CR0_AM_BIT)
#define X86_CR0_NW_BIT		(29)
#define X86_CR0_NW		BIT(X86_CR0_NW_BIT)
#define X86_CR0_CD_BIT		(30)
#define X86_CR0_CD		BIT(X86_CR0_CD_BIT)
#define X86_CR0_PG_BIT		(31)
#define X86_CR0_PG		BIT(X86_CR0_PG_BIT)

#define X86_CR3_PCID_MASK	GENMASK(11, 0)

#define X86_CR4_VME_BIT		(0)
#define X86_CR4_VME		BIT(X86_CR4_VME_BIT)
#define X86_CR4_PVI_BIT		(1)
#define X86_CR4_PVI		BIT(X86_CR4_PVI_BIT)
#define X86_CR4_TSD_BIT		(2)
#define X86_CR4_TSD		BIT(X86_CR4_TSD_BIT)
#define X86_CR4_DE_BIT		(3)
#define X86_CR4_DE		BIT(X86_CR4_DE_BIT)
#define X86_CR4_PSE_BIT		(4)
#define X86_CR4_PSE		BIT(X86_CR4_PSE_BIT)
#define X86_CR4_PAE_BIT		(5)
#define X86_CR4_PAE		BIT(X86_CR4_PAE_BIT)
#define X86_CR4_MCE_BIT		(6)
#define X86_CR4_MCE		BIT(X86_CR4_MCE_BIT)
#define X86_CR4_PGE_BIT		(7)
#define X86_CR4_PGE		BIT(X86_CR4_PGE_BIT)
#define X86_CR4_PCE_BIT		(8)
#define X86_CR4_PCE		BIT(X86_CR4_PCE_BIT)
#define X86_CR4_OSFXSR_BIT	(9)
#define X86_CR4_OSFXSR		BIT(X86_CR4_OSFXSR_BIT)
#define X86_CR4_OSXMMEXCPT_BIT	(10)
#define X86_CR4_OSXMMEXCPT	BIT(X86_CR4_OSXMMEXCPT_BIT)
#define X86_CR4_UMIP_BIT	(11)
#define X86_CR4_UMIP		BIT(X86_CR4_UMIP_BIT)
#define X86_CR4_LA57_BIT	(12)
#define X86_CR4_LA57		BIT(X86_CR4_LA57_BIT)
#define X86_CR4_VMXE_BIT	(13)
#define X86_CR4_VMXE		BIT(X86_CR4_VMXE_BIT)
#define X86_CR4_SMXE_BIT	(14)
#define X86_CR4_SMXE		BIT(X86_CR4_SMXE_BIT)
/* UNUSED			(15) */
#define X86_CR4_FSGSBASE_BIT	(16)
#define X86_CR4_FSGSBASE	BIT(X86_CR4_FSGSBASE_BIT)
#define X86_CR4_PCIDE_BIT	(17)
#define X86_CR4_PCIDE		BIT(X86_CR4_PCIDE_BIT)
#define X86_CR4_OSXSAVE_BIT	(18)
#define X86_CR4_OSXSAVE		BIT(X86_CR4_OSXSAVE_BIT)
#define X86_CR4_KL_BIT		(19)
#define X86_CR4_KL		BIT(X86_CR4_KL_BIT)
#define X86_CR4_SMEP_BIT	(20)
#define X86_CR4_SMEP		BIT(X86_CR4_SMEP_BIT)
#define X86_CR4_SMAP_BIT	(21)
#define X86_CR4_SMAP		BIT(X86_CR4_SMAP_BIT)
#define X86_CR4_PKE_BIT		(22)
#define X86_CR4_PKE		BIT(X86_CR4_PKE_BIT)
#define X86_CR4_CET_BIT		(23)
#define X86_CR4_CET		BIT(X86_CR4_CET_BIT)
#define X86_CR4_PKS_BIT		(24)
#define X86_CR4_PKS		BIT(X86_CR4_PKS_BIT)

#define X86_EFLAGS_CF_BIT	(0)
#define X86_EFLAGS_CF		BIT(X86_EFLAGS_CF_BIT)
#define X86_EFLAGS_FIXED_BIT	(1)
#define X86_EFLAGS_FIXED	BIT(X86_EFLAGS_FIXED_BIT)
#define X86_EFLAGS_PF_BIT	(2)
#define X86_EFLAGS_PF		BIT(X86_EFLAGS_PF_BIT)
/* RESERVED 0			(3) */
#define X86_EFLAGS_AF_BIT	(4)
#define X86_EFLAGS_AF		BIT(X86_EFLAGS_AF_BIT)
/* RESERVED 0			(5) */
#define X86_EFLAGS_ZF_BIT	(6)
#define X86_EFLAGS_ZF		BIT(X86_EFLAGS_ZF_BIT)
#define X86_EFLAGS_SF_BIT	(7)
#define X86_EFLAGS_SF		BIT(X86_EFLAGS_SF_BIT)
#define X86_EFLAGS_TF_BIT	(8)
#define X86_EFLAGS_TF		BIT(X86_EFLAGS_TF_BIT)
#define X86_EFLAGS_IF_BIT	(9)
#define X86_EFLAGS_IF		BIT(X86_EFLAGS_IF_BIT)
#define X86_EFLAGS_DF_BIT	(10)
#define X86_EFLAGS_DF		BIT(X86_EFLAGS_DF_BIT)
#define X86_EFLAGS_OF_BIT	(11)
#define X86_EFLAGS_OF		BIT(X86_EFLAGS_OF_BIT)
#define X86_EFLAGS_IOPL		GENMASK(13, 12)
#define X86_EFLAGS_NT_BIT	(14)
#define X86_EFLAGS_NT		BIT(X86_EFLAGS_NT_BIT)
/* RESERVED 0			(15) */
#define X86_EFLAGS_RF_BIT	(16)
#define X86_EFLAGS_RF		BIT(X86_EFLAGS_RF_BIT)
#define X86_EFLAGS_VM_BIT	(17)
#define X86_EFLAGS_VM		BIT(X86_EFLAGS_VM_BIT)
#define X86_EFLAGS_AC_BIT	(18)
#define X86_EFLAGS_AC		BIT(X86_EFLAGS_AC_BIT)
#define X86_EFLAGS_VIF_BIT	(19)
#define X86_EFLAGS_VIF		BIT(X86_EFLAGS_VIF_BIT)
#define X86_EFLAGS_VIP_BIT	(20)
#define X86_EFLAGS_VIP		BIT(X86_EFLAGS_VIP_BIT)
#define X86_EFLAGS_ID_BIT	(21)
#define X86_EFLAGS_ID		BIT(X86_EFLAGS_ID_BIT)

#define X86_EFLAGS_ALU (X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | \
			X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF)


/*
 * CPU features
 */

enum cpuid_output_regs {
	EAX,
	EBX,
	ECX,
	EDX
};

struct cpuid { u32 a, b, c, d; };

static inline struct cpuid raw_cpuid(u32 function, u32 index)
{
	struct cpuid r;
	asm volatile ("cpuid"
		      : "=a"(r.a), "=b"(r.b), "=c"(r.c), "=d"(r.d)
		      : "0"(function), "2"(index));
	return r;
}

static inline struct cpuid cpuid_indexed(u32 function, u32 index)
{
	u32 level = raw_cpuid(function & 0xf0000000, 0).a;
	if (level < function)
	return (struct cpuid) { 0, 0, 0, 0 };
	return raw_cpuid(function, index);
}

static inline struct cpuid cpuid(u32 function)
{
	return cpuid_indexed(function, 0);
}

static inline u8 cpuid_maxphyaddr(void)
{
	if (raw_cpuid(0x80000000, 0).a < 0x80000008)
	return 36;
	return raw_cpuid(0x80000008, 0).a & 0xff;
}

static inline bool is_intel(void)
{
	struct cpuid c = cpuid(0);
	u32 name[4] = {c.b, c.d, c.c };

	return strcmp((char *)name, "GenuineIntel") == 0;
}

#define	CPUID(a, b, c, d) ((((unsigned long long) a) << 32) | (b << 16) | \
			  (c << 8) | d)

/*
 * Each X86_FEATURE_XXX definition is 64-bit and contains the following
 * CPUID meta-data:
 *
 * 	[63:32] :  input value for EAX
 * 	[31:16] :  input value for ECX
 * 	[15:8]  :  output register
 * 	[7:0]   :  bit position in output register
 */

/*
 * Basic Leafs, a.k.a. Intel defined
 */
#define	X86_FEATURE_MWAIT		(CPUID(0x1, 0, ECX, 3))
#define	X86_FEATURE_VMX			(CPUID(0x1, 0, ECX, 5))
#define	X86_FEATURE_PDCM		(CPUID(0x1, 0, ECX, 15))
#define	X86_FEATURE_PCID		(CPUID(0x1, 0, ECX, 17))
#define	X86_FEATURE_MOVBE		(CPUID(0x1, 0, ECX, 22))
#define	X86_FEATURE_TSC_DEADLINE_TIMER	(CPUID(0x1, 0, ECX, 24))
#define	X86_FEATURE_XSAVE		(CPUID(0x1, 0, ECX, 26))
#define	X86_FEATURE_OSXSAVE		(CPUID(0x1, 0, ECX, 27))
#define	X86_FEATURE_RDRAND		(CPUID(0x1, 0, ECX, 30))
#define	X86_FEATURE_MCE			(CPUID(0x1, 0, EDX, 7))
#define	X86_FEATURE_APIC		(CPUID(0x1, 0, EDX, 9))
#define	X86_FEATURE_CLFLUSH		(CPUID(0x1, 0, EDX, 19))
#define	X86_FEATURE_XMM			(CPUID(0x1, 0, EDX, 25))
#define	X86_FEATURE_XMM2		(CPUID(0x1, 0, EDX, 26))
#define	X86_FEATURE_TSC_ADJUST		(CPUID(0x7, 0, EBX, 1))
#define	X86_FEATURE_HLE			(CPUID(0x7, 0, EBX, 4))
#define	X86_FEATURE_SMEP		(CPUID(0x7, 0, EBX, 7))
#define	X86_FEATURE_INVPCID		(CPUID(0x7, 0, EBX, 10))
#define	X86_FEATURE_RTM			(CPUID(0x7, 0, EBX, 11))
#define	X86_FEATURE_SMAP		(CPUID(0x7, 0, EBX, 20))
#define	X86_FEATURE_PCOMMIT		(CPUID(0x7, 0, EBX, 22))
#define	X86_FEATURE_CLFLUSHOPT		(CPUID(0x7, 0, EBX, 23))
#define	X86_FEATURE_CLWB		(CPUID(0x7, 0, EBX, 24))
#define	X86_FEATURE_UMIP		(CPUID(0x7, 0, ECX, 2))
#define	X86_FEATURE_PKU			(CPUID(0x7, 0, ECX, 3))
#define	X86_FEATURE_LA57		(CPUID(0x7, 0, ECX, 16))
#define	X86_FEATURE_RDPID		(CPUID(0x7, 0, ECX, 22))
#define	X86_FEATURE_SHSTK		(CPUID(0x7, 0, ECX, 7))
#define	X86_FEATURE_IBT			(CPUID(0x7, 0, EDX, 20))
#define	X86_FEATURE_SPEC_CTRL		(CPUID(0x7, 0, EDX, 26))
#define	X86_FEATURE_ARCH_CAPABILITIES	(CPUID(0x7, 0, EDX, 29))
#define	X86_FEATURE_PKS			(CPUID(0x7, 0, ECX, 31))

/*
 * Extended Leafs, a.k.a. AMD defined
 */
#define	X86_FEATURE_SVM			(CPUID(0x80000001, 0, ECX, 2))
#define	X86_FEATURE_NX			(CPUID(0x80000001, 0, EDX, 20))
#define	X86_FEATURE_GBPAGES		(CPUID(0x80000001, 0, EDX, 26))
#define	X86_FEATURE_RDTSCP		(CPUID(0x80000001, 0, EDX, 27))
#define	X86_FEATURE_LM			(CPUID(0x80000001, 0, EDX, 29))
#define	X86_FEATURE_RDPRU		(CPUID(0x80000008, 0, EBX, 4))
#define	X86_FEATURE_AMD_IBPB		(CPUID(0x80000008, 0, EBX, 12))
#define	X86_FEATURE_NPT			(CPUID(0x8000000A, 0, EDX, 0))
#define	X86_FEATURE_LBRV		(CPUID(0x8000000A, 0, EDX, 1))
#define	X86_FEATURE_NRIPS		(CPUID(0x8000000A, 0, EDX, 3))
#define X86_FEATURE_TSCRATEMSR		(CPUID(0x8000000A, 0, EDX, 4))
#define X86_FEATURE_PAUSEFILTER		(CPUID(0x8000000A, 0, EDX, 10))
#define X86_FEATURE_PFTHRESHOLD		(CPUID(0x8000000A, 0, EDX, 12))
#define	X86_FEATURE_VGIF		(CPUID(0x8000000A, 0, EDX, 16))


static inline bool this_cpu_has(u64 feature)
{
	u32 input_eax = feature >> 32;
	u32 input_ecx = (feature >> 16) & 0xffff;
	u32 output_reg = (feature >> 8) & 0xff;
	u8 bit = feature & 0xff;
	struct cpuid c;
	u32 *tmp;

	c = cpuid_indexed(input_eax, input_ecx);
	tmp = (u32 *)&c;

	return ((*(tmp + (output_reg % 32))) & (1 << bit));
}

struct far_pointer32 {
	u32 offset;
	u16 selector;
} __attribute__((packed));

struct descriptor_table_ptr {
	u16 limit;
	ulong base;
} __attribute__((packed));

static inline void clac(void)
{
	asm volatile (".byte 0x0f, 0x01, 0xca" : : : "memory");
}

static inline void stac(void)
{
	asm volatile (".byte 0x0f, 0x01, 0xcb" : : : "memory");
}

static inline u16 read_cs(void)
{
	unsigned val;

	asm volatile ("mov %%cs, %0" : "=mr"(val));
	return val;
}

static inline u16 read_ds(void)
{
	unsigned val;

	asm volatile ("mov %%ds, %0" : "=mr"(val));
	return val;
}

static inline u16 read_es(void)
{
	unsigned val;

	asm volatile ("mov %%es, %0" : "=mr"(val));
	return val;
}

static inline u16 read_ss(void)
{
	unsigned val;

	asm volatile ("mov %%ss, %0" : "=mr"(val));
	return val;
}

static inline u16 read_fs(void)
{
	unsigned val;

	asm volatile ("mov %%fs, %0" : "=mr"(val));
	return val;
}

static inline u16 read_gs(void)
{
	unsigned val;

	asm volatile ("mov %%gs, %0" : "=mr"(val));
	return val;
}

static inline unsigned long read_rflags(void)
{
	unsigned long f;
	asm volatile ("pushf; pop %0\n\t" : "=rm"(f));
	return f;
}

static inline void write_ds(unsigned val)
{
	asm volatile ("mov %0, %%ds" : : "rm"(val) : "memory");
}

static inline void write_es(unsigned val)
{
	asm volatile ("mov %0, %%es" : : "rm"(val) : "memory");
}

static inline void write_ss(unsigned val)
{
	asm volatile ("mov %0, %%ss" : : "rm"(val) : "memory");
}

static inline void write_fs(unsigned val)
{
	asm volatile ("mov %0, %%fs" : : "rm"(val) : "memory");
}

static inline void write_gs(unsigned val)
{
	asm volatile ("mov %0, %%gs" : : "rm"(val) : "memory");
}

static inline void write_rflags(unsigned long f)
{
	asm volatile ("push %0; popf\n\t" : : "rm"(f));
}

static inline void set_iopl(int iopl)
{
	unsigned long flags = read_rflags() & ~X86_EFLAGS_IOPL;
	flags |= iopl * (X86_EFLAGS_IOPL / 3);
	write_rflags(flags);
}

/*
 * Don't use the safe variants for rdmsr() or wrmsr().  The exception fixup
 * infrastructure uses per-CPU data and thus consumes GS.base.  Various tests
 * temporarily modify MSR_GS_BASE and will explode when trying to determine
 * whether or not RDMSR/WRMSR faulted.
 */
static inline u64 rdmsr(u32 index)
{
	u32 a, d;
	asm volatile ("rdmsr" : "=a"(a), "=d"(d) : "c"(index) : "memory");
	return a | ((u64)d << 32);
}

static inline void wrmsr(u32 index, u64 val)
{
	u32 a = val, d = val >> 32;
	asm volatile ("wrmsr" : : "a"(a), "d"(d), "c"(index) : "memory");
}

static inline int rdmsr_safe(u32 index, uint64_t *val)
{
	uint32_t a, d;

	asm volatile (ASM_TRY("1f")
		      "rdmsr\n\t"
		      "1:"
		      : "=a"(a), "=d"(d)
		      : "c"(index) : "memory");

	*val = (uint64_t)a | ((uint64_t)d << 32);
	return exception_vector();
}

static inline int wrmsr_safe(u32 index, u64 val)
{
	u32 a = val, d = val >> 32;

	asm volatile (ASM_TRY("1f")
		      "wrmsr\n\t"
		      "1:"
		      : : "a"(a), "d"(d), "c"(index) : "memory");
	return exception_vector();
}

static inline uint64_t rdpmc(uint32_t index)
{
	uint32_t a, d;
	asm volatile ("rdpmc" : "=a"(a), "=d"(d) : "c"(index));
	return a | ((uint64_t)d << 32);
}

static inline int write_cr0_safe(ulong val)
{
	asm volatile(ASM_TRY("1f")
		     "mov %0,%%cr0\n\t"
		     "1:": : "r" (val));
	return exception_vector();
}

static inline void write_cr0(ulong val)
{
	int vector = write_cr0_safe(val);

	assert_msg(!vector, "Unexpected fault '%d' writing CR0 = %lx",
		   vector, val);
}

static inline ulong read_cr0(void)
{
	ulong val;
	asm volatile ("mov %%cr0, %0" : "=r"(val) : : "memory");
	return val;
}

static inline void write_cr2(ulong val)
{
	asm volatile ("mov %0, %%cr2" : : "r"(val) : "memory");
}

static inline ulong read_cr2(void)
{
	ulong val;
	asm volatile ("mov %%cr2, %0" : "=r"(val) : : "memory");
	return val;
}

static inline int write_cr3_safe(ulong val)
{
	asm volatile(ASM_TRY("1f")
		     "mov %0,%%cr3\n\t"
		     "1:": : "r" (val));
	return exception_vector();
}

static inline void write_cr3(ulong val)
{
	int vector = write_cr3_safe(val);

	assert_msg(!vector, "Unexpected fault '%d' writing CR3 = %lx",
		   vector, val);
}

static inline ulong read_cr3(void)
{
	ulong val;
	asm volatile ("mov %%cr3, %0" : "=r"(val) : : "memory");
	return val;
}

static inline void update_cr3(void *cr3)
{
	write_cr3((ulong)cr3);
}

static inline int write_cr4_safe(ulong val)
{
	asm volatile(ASM_TRY("1f")
		     "mov %0,%%cr4\n\t"
		     "1:": : "r" (val));
	return exception_vector();
}

static inline void write_cr4(ulong val)
{
	int vector = write_cr4_safe(val);

	assert_msg(!vector, "Unexpected fault '%d' writing CR4 = %lx",
		   vector, val);
}

static inline ulong read_cr4(void)
{
	ulong val;
	asm volatile ("mov %%cr4, %0" : "=r"(val) : : "memory");
	return val;
}

static inline void write_cr8(ulong val)
{
	asm volatile ("mov %0, %%cr8" : : "r"(val) : "memory");
}

static inline ulong read_cr8(void)
{
	ulong val;
	asm volatile ("mov %%cr8, %0" : "=r"(val) : : "memory");
	return val;
}

static inline void lgdt(const struct descriptor_table_ptr *ptr)
{
	asm volatile ("lgdt %0" : : "m"(*ptr));
}

static inline void sgdt(struct descriptor_table_ptr *ptr)
{
	asm volatile ("sgdt %0" : "=m"(*ptr));
}

static inline void lidt(const struct descriptor_table_ptr *ptr)
{
	asm volatile ("lidt %0" : : "m"(*ptr));
}

static inline void sidt(struct descriptor_table_ptr *ptr)
{
	asm volatile ("sidt %0" : "=m"(*ptr));
}

static inline void lldt(u16 val)
{
	asm volatile ("lldt %0" : : "rm"(val));
}

static inline u16 sldt(void)
{
	u16 val;
	asm volatile ("sldt %0" : "=rm"(val));
	return val;
}

static inline void ltr(u16 val)
{
	asm volatile ("ltr %0" : : "rm"(val));
}

static inline u16 str(void)
{
	u16 val;
	asm volatile ("str %0" : "=rm"(val));
	return val;
}

static inline void write_dr0(void *val)
{
	asm volatile ("mov %0, %%dr0" : : "r"(val) : "memory");
}

static inline void write_dr1(void *val)
{
	asm volatile ("mov %0, %%dr1" : : "r"(val) : "memory");
}

static inline void write_dr2(void *val)
{
	asm volatile ("mov %0, %%dr2" : : "r"(val) : "memory");
}

static inline void write_dr3(void *val)
{
	asm volatile ("mov %0, %%dr3" : : "r"(val) : "memory");
}

static inline void write_dr6(ulong val)
{
	asm volatile ("mov %0, %%dr6" : : "r"(val) : "memory");
}

static inline ulong read_dr6(void)
{
	ulong val;
	asm volatile ("mov %%dr6, %0" : "=r"(val));
	return val;
}

static inline void write_dr7(ulong val)
{
	asm volatile ("mov %0, %%dr7" : : "r"(val) : "memory");
}

static inline ulong read_dr7(void)
{
	ulong val;
	asm volatile ("mov %%dr7, %0" : "=r"(val));
	return val;
}

static inline void pause(void)
{
	asm volatile ("pause");
}

static inline void cli(void)
{
	asm volatile ("cli");
}

static inline void sti(void)
{
	asm volatile ("sti");
}

static inline unsigned long long rdrand(void)
{
	long long r;

	asm volatile("rdrand %0\n\t"
		     "jc 1f\n\t"
		     "mov $0, %0\n\t"
		     "1:\n\t" : "=r" (r));
	return r;
}

static inline unsigned long long rdtsc(void)
{
	long long r;

#ifdef __x86_64__
	unsigned a, d;

	asm volatile ("rdtsc" : "=a"(a), "=d"(d));
	r = a | ((long long)d << 32);
#else
	asm volatile ("rdtsc" : "=A"(r));
#endif
	return r;
}

/*
 * Per the advice in the SDM, volume 2, the sequence "mfence; lfence"
 * executed immediately before rdtsc ensures that rdtsc will be
 * executed only after all previous instructions have executed and all
 * previous loads and stores are globally visible. In addition, the
 * lfence immediately after rdtsc ensures that rdtsc will be executed
 * prior to the execution of any subsequent instruction.
 */
static inline unsigned long long fenced_rdtsc(void)
{
	unsigned long long tsc;

#ifdef __x86_64__
	unsigned int eax, edx;

	asm volatile ("mfence; lfence; rdtsc; lfence" : "=a"(eax), "=d"(edx));
	tsc = eax | ((unsigned long long)edx << 32);
#else
	asm volatile ("mfence; lfence; rdtsc; lfence" : "=A"(tsc));
#endif
	return tsc;
}

static inline unsigned long long rdtscp(u32 *aux)
{
	long long r;

#ifdef __x86_64__
	unsigned a, d;

	asm volatile ("rdtscp" : "=a"(a), "=d"(d), "=c"(*aux));
	r = a | ((long long)d << 32);
#else
	asm volatile ("rdtscp" : "=A"(r), "=c"(*aux));
#endif
	return r;
}

static inline void wrtsc(u64 tsc)
{
	wrmsr(MSR_IA32_TSC, tsc);
}

static inline void irq_disable(void)
{
	asm volatile("cli");
}

/* Note that irq_enable() does not ensure an interrupt shadow due
 * to the vagaries of compiler optimizations.  If you need the
 * shadow, use a single asm with "sti" and the instruction after it.
 */
static inline void irq_enable(void)
{
	asm volatile("sti");
}

static inline void invlpg(volatile void *va)
{
	asm volatile("invlpg (%0)" ::"r" (va) : "memory");
}

static inline void safe_halt(void)
{
	asm volatile("sti; hlt");
}

static inline u32 read_pkru(void)
{
	unsigned int eax, edx;
	unsigned int ecx = 0;
	unsigned int pkru;

	asm volatile(".byte 0x0f,0x01,0xee\n\t"
		     : "=a" (eax), "=d" (edx)
		     : "c" (ecx));
	pkru = eax;
	return pkru;
}

static inline void write_pkru(u32 pkru)
{
	unsigned int eax = pkru;
	unsigned int ecx = 0;
	unsigned int edx = 0;

	asm volatile(".byte 0x0f,0x01,0xef\n\t"
		     : : "a" (eax), "c" (ecx), "d" (edx));
}

static inline bool is_canonical(u64 addr)
{
	int va_width = (raw_cpuid(0x80000008, 0).a & 0xff00) >> 8;
	int shift_amt = 64 - va_width;

	return (s64)(addr << shift_amt) >> shift_amt == addr;
}

static inline void clear_bit(int bit, u8 *addr)
{
	__asm__ __volatile__("btr %1, %0"
			     : "+m" (*addr) : "Ir" (bit) : "cc", "memory");
}

static inline void set_bit(int bit, u8 *addr)
{
	__asm__ __volatile__("bts %1, %0"
			     : "+m" (*addr) : "Ir" (bit) : "cc", "memory");
}

static inline void flush_tlb(void)
{
	ulong cr4;

	cr4 = read_cr4();
	write_cr4(cr4 ^ X86_CR4_PGE);
	write_cr4(cr4);
}

static inline void generate_non_canonical_gp(void)
{
	*(volatile u64 *)NONCANONICAL = 0;
}

static inline void generate_ud(void)
{
	asm volatile ("ud2");
}

static inline void generate_de(void)
{
	asm volatile (
		"xor %%eax, %%eax\n\t"
		"xor %%ebx, %%ebx\n\t"
		"xor %%edx, %%edx\n\t"
		"idiv %%ebx\n\t"
		::: "eax", "ebx", "edx");
}

static inline void generate_bp(void)
{
	asm volatile ("int3");
}

static inline void generate_single_step_db(void)
{
	write_rflags(read_rflags() | X86_EFLAGS_TF);
	asm volatile("nop");
}

static inline uint64_t generate_usermode_ac(void)
{
	/*
	 * Trigger an #AC by writing 8 bytes to a 4-byte aligned address.
	 * Disclaimer: It is assumed that the stack pointer is aligned
	 * on a 16-byte boundary as x86_64 stacks should be.
	 */
	asm volatile("movq $0, -0x4(%rsp)");

	return 0;
}

/*
 * Switch from 64-bit to 32-bit mode and generate #OF via INTO.  Note, if RIP
 * or RSP holds a 64-bit value, this helper will NOT generate #OF.
 */
static inline void generate_of(void)
{
	struct far_pointer32 fp = {
		.offset = (uintptr_t)&&into,
		.selector = KERNEL_CS32,
	};
	uintptr_t rsp;

	asm volatile ("mov %%rsp, %0" : "=r"(rsp));

	if (fp.offset != (uintptr_t)&&into) {
		printf("Code address too high.\n");
		return;
	}
	if ((u32)rsp != rsp) {
		printf("Stack address too high.\n");
		return;
	}

	asm goto ("lcall *%0" : : "m" (fp) : "rax" : into);
	return;
into:
	asm volatile (".code32;"
		      "movl $0x7fffffff, %eax;"
		      "addl %eax, %eax;"
		      "into;"
		      "lret;"
		      ".code64");
	__builtin_unreachable();
}

static inline void fnop(void)
{
	asm volatile("fnop");
}

/* If CR0.TS is set in L2, #NM is generated. */
static inline void generate_cr0_ts_nm(void)
{
	write_cr0((read_cr0() & ~X86_CR0_EM) | X86_CR0_TS);
	fnop();
}

/* If CR0.TS is cleared and CR0.EM is set, #NM is generated. */
static inline void generate_cr0_em_nm(void)
{
	write_cr0((read_cr0() & ~X86_CR0_TS) | X86_CR0_EM);
	fnop();
}

static inline u8 pmu_version(void)
{
	return cpuid(10).a & 0xff;
}

static inline bool this_cpu_has_pmu(void)
{
	return !!pmu_version();
}

static inline bool this_cpu_has_perf_global_ctrl(void)
{
	return pmu_version() > 1;
}

static inline u8 pmu_nr_gp_counters(void)
{
	return (cpuid(10).a >> 8) & 0xff;
}

static inline u8 pmu_gp_counter_width(void)
{
	return (cpuid(10).a >> 16) & 0xff;
}

static inline u8 pmu_gp_counter_mask_length(void)
{
	return (cpuid(10).a >> 24) & 0xff;
}

static inline u8 pmu_nr_fixed_counters(void)
{
	struct cpuid id = cpuid(10);

	if ((id.a & 0xff) > 1)
		return id.d & 0x1f;
	else
		return 0;
}

static inline u8 pmu_fixed_counter_width(void)
{
	struct cpuid id = cpuid(10);

	if ((id.a & 0xff) > 1)
		return (id.d >> 5) & 0xff;
	else
		return 0;
}

static inline bool pmu_gp_counter_is_available(int i)
{
	/* CPUID.0xA.EBX bit is '1 if they counter is NOT available. */
	return !(cpuid(10).b & BIT(i));
}

#endif
