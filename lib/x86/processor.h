#ifndef _X86_PROCESSOR_H_
#define _X86_PROCESSOR_H_

#include "libcflat.h"
#include "desc.h"
#include "msr.h"
#include <bitops.h>
#include <stdint.h>
#include <util.h>

#define CANONICAL_48_VAL 0xffffaaaaaaaaaaaaull
#define CANONICAL_57_VAL 0xffaaaaaaaaaaaaaaull
#define NONCANONICAL	 0xaaaaaaaaaaaaaaaaull

#define LAM57_MASK	GENMASK_ULL(62, 57)
#define LAM48_MASK	GENMASK_ULL(62, 48)

/*
 * Get a linear address by combining @addr with a non-canonical pattern in the
 * @mask bits.
 */
static inline u64 get_non_canonical(u64 addr, u64 mask)
{
	return (addr & ~mask) | (NONCANONICAL & mask);
}

#ifdef __x86_64__
#  define R "r"
#  define W "q"
#  define S "8"
#else
#  define R "e"
#  define W "l"
#  define S "4"
#endif

#define DE_VECTOR 0
#define DB_VECTOR 1
#define NMI_VECTOR 2
#define BP_VECTOR 3
#define OF_VECTOR 4
#define BR_VECTOR 5
#define UD_VECTOR 6
#define NM_VECTOR 7
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define MF_VECTOR 16
#define AC_VECTOR 17
#define MC_VECTOR 18
#define XM_VECTOR 19
#define XF_VECTOR XM_VECTOR /* AMD */
#define VE_VECTOR 20 /* Intel only */
#define CP_VECTOR 21
#define HV_VECTOR 28 /* AMD only */
#define VC_VECTOR 29 /* AMD only */
#define SX_VECTOR 30 /* AMD only */

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
#define X86_CR3_LAM_U57_BIT	(61)
#define X86_CR3_LAM_U57		BIT_ULL(X86_CR3_LAM_U57_BIT)
#define X86_CR3_LAM_U48_BIT	(62)
#define X86_CR3_LAM_U48		BIT_ULL(X86_CR3_LAM_U48_BIT)

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
#define X86_CR4_LAM_SUP_BIT	(28)
#define X86_CR4_LAM_SUP		BIT(X86_CR4_LAM_SUP_BIT)

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

static inline bool is_intel(void)
{
	struct cpuid c = cpuid(0);
	u32 name[4] = {c.b, c.d, c.c };

	return strcmp((char *)name, "GenuineIntel") == 0;
}

/*
 * Pack the information into a 64-bit value so that each X86_FEATURE_XXX can be
 * passed by value with no overhead.
 */
struct x86_cpu_feature {
	u32	function;
	u16	index;
	u8	reg;
	u8	bit;
};

#define X86_CPU_FEATURE(fn, idx, gpr, __bit)					\
({										\
	struct x86_cpu_feature feature = {					\
		.function = fn,							\
		.index = idx,							\
		.reg = gpr,							\
		.bit = __bit,							\
	};									\
										\
	static_assert((fn & 0xc0000000) == 0 ||					\
		      (fn & 0xc0000000) == 0x40000000 ||			\
		      (fn & 0xc0000000) == 0x80000000 ||			\
		      (fn & 0xc0000000) == 0xc0000000);				\
	static_assert(idx < BIT(sizeof(feature.index) * BITS_PER_BYTE));	\
	feature;								\
})

/*
 * Basic Leafs, a.k.a. Intel defined
 */
#define X86_FEATURE_MWAIT		X86_CPU_FEATURE(0x1, 0, ECX, 3)
#define X86_FEATURE_VMX			X86_CPU_FEATURE(0x1, 0, ECX, 5)
#define X86_FEATURE_PDCM		X86_CPU_FEATURE(0x1, 0, ECX, 15)
#define X86_FEATURE_PCID		X86_CPU_FEATURE(0x1, 0, ECX, 17)
#define X86_FEATURE_X2APIC		X86_CPU_FEATURE(0x1, 0, ECX, 21)
#define X86_FEATURE_MOVBE		X86_CPU_FEATURE(0x1, 0, ECX, 22)
#define X86_FEATURE_TSC_DEADLINE_TIMER	X86_CPU_FEATURE(0x1, 0, ECX, 24)
#define X86_FEATURE_XSAVE		X86_CPU_FEATURE(0x1, 0, ECX, 26)
#define X86_FEATURE_OSXSAVE		X86_CPU_FEATURE(0x1, 0, ECX, 27)
#define X86_FEATURE_RDRAND		X86_CPU_FEATURE(0x1, 0, ECX, 30)
#define X86_FEATURE_MCE			X86_CPU_FEATURE(0x1, 0, EDX, 7)
#define X86_FEATURE_APIC		X86_CPU_FEATURE(0x1, 0, EDX, 9)
#define X86_FEATURE_CLFLUSH		X86_CPU_FEATURE(0x1, 0, EDX, 19)
#define X86_FEATURE_DS			X86_CPU_FEATURE(0x1, 0, EDX, 21)
#define X86_FEATURE_XMM			X86_CPU_FEATURE(0x1, 0, EDX, 25)
#define X86_FEATURE_XMM2		X86_CPU_FEATURE(0x1, 0, EDX, 26)
#define X86_FEATURE_TSC_ADJUST		X86_CPU_FEATURE(0x7, 0, EBX, 1)
#define X86_FEATURE_HLE			X86_CPU_FEATURE(0x7, 0, EBX, 4)
#define X86_FEATURE_SMEP		X86_CPU_FEATURE(0x7, 0, EBX, 7)
#define X86_FEATURE_INVPCID		X86_CPU_FEATURE(0x7, 0, EBX, 10)
#define X86_FEATURE_RTM			X86_CPU_FEATURE(0x7, 0, EBX, 11)
#define X86_FEATURE_SMAP		X86_CPU_FEATURE(0x7, 0, EBX, 20)
#define X86_FEATURE_PCOMMIT		X86_CPU_FEATURE(0x7, 0, EBX, 22)
#define X86_FEATURE_CLFLUSHOPT		X86_CPU_FEATURE(0x7, 0, EBX, 23)
#define X86_FEATURE_CLWB		X86_CPU_FEATURE(0x7, 0, EBX, 24)
#define X86_FEATURE_INTEL_PT		X86_CPU_FEATURE(0x7, 0, EBX, 25)
#define X86_FEATURE_UMIP		X86_CPU_FEATURE(0x7, 0, ECX, 2)
#define X86_FEATURE_PKU			X86_CPU_FEATURE(0x7, 0, ECX, 3)
#define X86_FEATURE_LA57		X86_CPU_FEATURE(0x7, 0, ECX, 16)
#define X86_FEATURE_RDPID		X86_CPU_FEATURE(0x7, 0, ECX, 22)
#define X86_FEATURE_SHSTK		X86_CPU_FEATURE(0x7, 0, ECX, 7)
#define X86_FEATURE_IBT			X86_CPU_FEATURE(0x7, 0, EDX, 20)
#define X86_FEATURE_SPEC_CTRL		X86_CPU_FEATURE(0x7, 0, EDX, 26)
#define X86_FEATURE_FLUSH_L1D		X86_CPU_FEATURE(0x7, 0, EDX, 28)
#define X86_FEATURE_ARCH_CAPABILITIES	X86_CPU_FEATURE(0x7, 0, EDX, 29)
#define X86_FEATURE_PKS			X86_CPU_FEATURE(0x7, 0, ECX, 31)
#define X86_FEATURE_LAM			X86_CPU_FEATURE(0x7, 1, EAX, 26)

/*
 * KVM defined leafs
 */
#define KVM_FEATURE_ASYNC_PF		X86_CPU_FEATURE(0x40000001, 0, EAX, 4)
#define KVM_FEATURE_ASYNC_PF_INT	X86_CPU_FEATURE(0x40000001, 0, EAX, 14)

/*
 * Extended Leafs, a.k.a. AMD defined
 */
#define X86_FEATURE_SVM			X86_CPU_FEATURE(0x80000001, 0, ECX, 2)
#define X86_FEATURE_PERFCTR_CORE	X86_CPU_FEATURE(0x80000001, 0, ECX, 23)
#define X86_FEATURE_NX			X86_CPU_FEATURE(0x80000001, 0, EDX, 20)
#define X86_FEATURE_GBPAGES		X86_CPU_FEATURE(0x80000001, 0, EDX, 26)
#define X86_FEATURE_RDTSCP		X86_CPU_FEATURE(0x80000001, 0, EDX, 27)
#define X86_FEATURE_LM			X86_CPU_FEATURE(0x80000001, 0, EDX, 29)
#define X86_FEATURE_RDPRU		X86_CPU_FEATURE(0x80000008, 0, EBX, 4)
#define X86_FEATURE_AMD_IBPB		X86_CPU_FEATURE(0x80000008, 0, EBX, 12)
#define X86_FEATURE_NPT			X86_CPU_FEATURE(0x8000000A, 0, EDX, 0)
#define X86_FEATURE_LBRV		X86_CPU_FEATURE(0x8000000A, 0, EDX, 1)
#define X86_FEATURE_NRIPS		X86_CPU_FEATURE(0x8000000A, 0, EDX, 3)
#define X86_FEATURE_TSCRATEMSR		X86_CPU_FEATURE(0x8000000A, 0, EDX, 4)
#define X86_FEATURE_PAUSEFILTER		X86_CPU_FEATURE(0x8000000A, 0, EDX, 10)
#define X86_FEATURE_PFTHRESHOLD		X86_CPU_FEATURE(0x8000000A, 0, EDX, 12)
#define X86_FEATURE_VGIF		X86_CPU_FEATURE(0x8000000A, 0, EDX, 16)
#define X86_FEATURE_VNMI		X86_CPU_FEATURE(0x8000000A, 0, EDX, 25)
#define X86_FEATURE_SME			X86_CPU_FEATURE(0x8000001F, 0, EAX,  0)
#define X86_FEATURE_SEV			X86_CPU_FEATURE(0x8000001F, 0, EAX,  1)
#define X86_FEATURE_VM_PAGE_FLUSH	X86_CPU_FEATURE(0x8000001F, 0, EAX,  2)
#define X86_FEATURE_SEV_ES		X86_CPU_FEATURE(0x8000001F, 0, EAX,  3)
#define X86_FEATURE_SEV_SNP		X86_CPU_FEATURE(0x8000001F, 0, EAX,  4)
#define X86_FEATURE_V_TSC_AUX		X86_CPU_FEATURE(0x8000001F, 0, EAX,  9)
#define X86_FEATURE_SME_COHERENT	X86_CPU_FEATURE(0x8000001F, 0, EAX, 10)
#define X86_FEATURE_DEBUG_SWAP		X86_CPU_FEATURE(0x8000001F, 0, EAX, 14)
#define X86_FEATURE_SVSM		X86_CPU_FEATURE(0x8000001F, 0, EAX, 28)
#define X86_FEATURE_AMD_PMU_V2		X86_CPU_FEATURE(0x80000022, 0, EAX, 0)

/*
 * Same idea as X86_FEATURE_XXX, but X86_PROPERTY_XXX retrieves a multi-bit
 * value/property as opposed to a single-bit feature.  Again, pack the info
 * into a 64-bit value to pass by value with no overhead on 64-bit builds.
 */
struct x86_cpu_property {
	u32	function;
	u8	index;
	u8	reg;
	u8	lo_bit;
	u8	hi_bit;
};
#define X86_CPU_PROPERTY(fn, idx, gpr, low_bit, high_bit)			\
({										\
	struct x86_cpu_property property = {					\
		.function = fn,							\
		.index = idx,							\
		.reg = gpr,							\
		.lo_bit = low_bit,						\
		.hi_bit = high_bit,						\
	};									\
										\
	static_assert(low_bit < high_bit);					\
	static_assert((fn & 0xc0000000) == 0 ||					\
		      (fn & 0xc0000000) == 0x40000000 ||			\
		      (fn & 0xc0000000) == 0x80000000 ||			\
		      (fn & 0xc0000000) == 0xc0000000);				\
	static_assert(idx < BIT(sizeof(property.index) * BITS_PER_BYTE));	\
	property;								\
})

#define X86_PROPERTY_MAX_BASIC_LEAF		X86_CPU_PROPERTY(0, 0, EAX, 0, 31)
#define X86_PROPERTY_PMU_VERSION		X86_CPU_PROPERTY(0xa, 0, EAX, 0, 7)
#define X86_PROPERTY_PMU_NR_GP_COUNTERS		X86_CPU_PROPERTY(0xa, 0, EAX, 8, 15)
#define X86_PROPERTY_PMU_GP_COUNTERS_BIT_WIDTH	X86_CPU_PROPERTY(0xa, 0, EAX, 16, 23)
#define X86_PROPERTY_PMU_EBX_BIT_VECTOR_LENGTH	X86_CPU_PROPERTY(0xa, 0, EAX, 24, 31)
#define X86_PROPERTY_PMU_EVENTS_MASK		X86_CPU_PROPERTY(0xa, 0, EBX, 0, 7)
#define X86_PROPERTY_PMU_FIXED_COUNTERS_BITMASK	X86_CPU_PROPERTY(0xa, 0, ECX, 0, 31)
#define X86_PROPERTY_PMU_NR_FIXED_COUNTERS	X86_CPU_PROPERTY(0xa, 0, EDX, 0, 4)
#define X86_PROPERTY_PMU_FIXED_COUNTERS_BIT_WIDTH	X86_CPU_PROPERTY(0xa, 0, EDX, 5, 12)

#define X86_PROPERTY_SUPPORTED_XCR0_LO		X86_CPU_PROPERTY(0xd,  0, EAX,  0, 31)
#define X86_PROPERTY_XSTATE_MAX_SIZE_XCR0	X86_CPU_PROPERTY(0xd,  0, EBX,  0, 31)
#define X86_PROPERTY_XSTATE_MAX_SIZE		X86_CPU_PROPERTY(0xd,  0, ECX,  0, 31)
#define X86_PROPERTY_SUPPORTED_XCR0_HI		X86_CPU_PROPERTY(0xd,  0, EDX,  0, 31)

#define X86_PROPERTY_XSTATE_TILE_SIZE		X86_CPU_PROPERTY(0xd, 18, EAX,  0, 31)
#define X86_PROPERTY_XSTATE_TILE_OFFSET		X86_CPU_PROPERTY(0xd, 18, EBX,  0, 31)

#define X86_PROPERTY_INTEL_PT_NR_RANGES		X86_CPU_PROPERTY(0x14, 1, EAX,  0, 2)

#define X86_PROPERTY_AMX_MAX_PALETTE_TABLES	X86_CPU_PROPERTY(0x1d, 0, EAX,  0, 31)
#define X86_PROPERTY_AMX_TOTAL_TILE_BYTES	X86_CPU_PROPERTY(0x1d, 1, EAX,  0, 15)
#define X86_PROPERTY_AMX_BYTES_PER_TILE		X86_CPU_PROPERTY(0x1d, 1, EAX, 16, 31)
#define X86_PROPERTY_AMX_BYTES_PER_ROW		X86_CPU_PROPERTY(0x1d, 1, EBX, 0,  15)
#define X86_PROPERTY_AMX_NR_TILE_REGS		X86_CPU_PROPERTY(0x1d, 1, EBX, 16, 31)
#define X86_PROPERTY_AMX_MAX_ROWS		X86_CPU_PROPERTY(0x1d, 1, ECX, 0,  15)

#define X86_PROPERTY_MAX_KVM_LEAF		X86_CPU_PROPERTY(0x40000000, 0, EAX, 0, 31)

#define X86_PROPERTY_MAX_EXT_LEAF		X86_CPU_PROPERTY(0x80000000, 0, EAX, 0, 31)
#define X86_PROPERTY_MAX_PHY_ADDR		X86_CPU_PROPERTY(0x80000008, 0, EAX, 0, 7)
#define X86_PROPERTY_MAX_VIRT_ADDR		X86_CPU_PROPERTY(0x80000008, 0, EAX, 8, 15)
#define X86_PROPERTY_GUEST_MAX_PHY_ADDR		X86_CPU_PROPERTY(0x80000008, 0, EAX, 16, 23)
#define X86_PROPERTY_SEV_C_BIT			X86_CPU_PROPERTY(0x8000001F, 0, EBX, 0, 5)
#define X86_PROPERTY_PHYS_ADDR_REDUCTION	X86_CPU_PROPERTY(0x8000001F, 0, EBX, 6, 11)
#define X86_PROPERTY_NR_PERFCTR_CORE		X86_CPU_PROPERTY(0x80000022, 0, EBX, 0, 3)
#define X86_PROPERTY_NR_PERFCTR_NB		X86_CPU_PROPERTY(0x80000022, 0, EBX, 10, 15)

#define X86_PROPERTY_MAX_CENTAUR_LEAF		X86_CPU_PROPERTY(0xC0000000, 0, EAX, 0, 31)

static inline u32 __this_cpu_has(u32 function, u32 index, u8 reg, u8 lo, u8 hi)
{
	union {
		struct cpuid cpuid;
		u32 gprs[4];
	} c;

	c.cpuid = cpuid_indexed(function, index);

	return (c.gprs[reg] & GENMASK(hi, lo)) >> lo;
}

static inline bool this_cpu_has(struct x86_cpu_feature feature)
{
	return __this_cpu_has(feature.function, feature.index,
			      feature.reg, feature.bit, feature.bit);
}

static inline uint32_t this_cpu_property(struct x86_cpu_property property)
{
	return __this_cpu_has(property.function, property.index,
			      property.reg, property.lo_bit, property.hi_bit);
}

static __always_inline bool this_cpu_has_p(struct x86_cpu_property property)
{
	uint32_t max_leaf;

	switch (property.function & 0xc0000000) {
	case 0:
		max_leaf = this_cpu_property(X86_PROPERTY_MAX_BASIC_LEAF);
		break;
	case 0x40000000:
		max_leaf = this_cpu_property(X86_PROPERTY_MAX_KVM_LEAF);
		break;
	case 0x80000000:
		max_leaf = this_cpu_property(X86_PROPERTY_MAX_EXT_LEAF);
		break;
	case 0xc0000000:
		max_leaf = this_cpu_property(X86_PROPERTY_MAX_CENTAUR_LEAF);
	}
	return max_leaf >= property.function;
}

static inline u8 cpuid_maxphyaddr(void)
{
	if (!this_cpu_has_p(X86_PROPERTY_MAX_PHY_ADDR))
		return 36;

	return this_cpu_property(X86_PROPERTY_MAX_PHY_ADDR);
}

static inline u64 this_cpu_supported_xcr0(void)
{
	if (!this_cpu_has_p(X86_PROPERTY_SUPPORTED_XCR0_LO))
		return 0;

	return (u64)this_cpu_property(X86_PROPERTY_SUPPORTED_XCR0_LO) |
	       ((u64)this_cpu_property(X86_PROPERTY_SUPPORTED_XCR0_HI) << 32);
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

#define __rdreg64_safe(fep, insn, index, val)				\
({									\
	uint32_t a, d;							\
	int vector;							\
									\
	vector = __asm_safe_out2(fep, insn, "=a"(a), "=d"(d), "c"(index));\
									\
	if (vector)							\
		*(val) = 0;						\
	else								\
		*(val) = (uint64_t)a | ((uint64_t)d << 32);		\
	vector;								\
})

#define rdreg64_safe(insn, index, val)					\
	__rdreg64_safe("", insn, index, val)

#define __wrreg64_safe(fep, insn, index, val)				\
({									\
	uint32_t eax = (val), edx = (val) >> 32;			\
									\
	__asm_safe(fep, insn, "a" (eax), "d" (edx), "c" (index));	\
})

#define wrreg64_safe(insn, index, val)					\
	__wrreg64_safe("", insn, index, val)

static inline int rdmsr_safe(u32 index, uint64_t *val)
{
	return rdreg64_safe("rdmsr", index, val);
}

static inline int rdmsr_fep_safe(u32 index, uint64_t *val)
{
	return __rdreg64_safe(KVM_FEP, "rdmsr", index, val);
}

static inline int wrmsr_safe(u32 index, u64 val)
{
	return wrreg64_safe("wrmsr", index, val);
}

static inline int wrmsr_fep_safe(u32 index, u64 val)
{
	return __wrreg64_safe(KVM_FEP, "wrmsr", index, val);
}

static inline int rdpmc_safe(u32 index, uint64_t *val)
{
	return rdreg64_safe("rdpmc", index, val);
}

static inline uint64_t rdpmc(uint32_t index)
{
	uint64_t val;
	int vector = rdpmc_safe(index, &val);

	assert_msg(!vector, "Unexpected %s on RDPMC(%" PRId32 ")",
		   exception_mnemonic(vector), index);
	return val;
}

static inline int xgetbv_safe(u32 index, u64 *result)
{
	return rdreg64_safe(".byte 0x0f,0x01,0xd0", index, result);
}

static inline int xsetbv_safe(u32 index, u64 value)
{
	return wrreg64_safe(".byte 0x0f,0x01,0xd1", index, value);
}

static inline int write_cr0_safe(ulong val)
{
	return asm_safe("mov %0,%%cr0", "r" (val));
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
	return asm_safe("mov %0,%%cr3", "r" (val));
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
	return asm_safe("mov %0,%%cr4", "r" (val));
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

static inline int lgdt_safe(const struct descriptor_table_ptr *ptr)
{
	return asm_safe("lgdt %0", "m"(*ptr));
}

static inline int lgdt_fep_safe(const struct descriptor_table_ptr *ptr)
{
	return asm_fep_safe("lgdt %0", "m"(*ptr));
}

static inline void sgdt(struct descriptor_table_ptr *ptr)
{
	asm volatile ("sgdt %0" : "=m"(*ptr));
}

static inline void lidt(const struct descriptor_table_ptr *ptr)
{
	asm volatile ("lidt %0" : : "m"(*ptr));
}

static inline int lidt_safe(const struct descriptor_table_ptr *ptr)
{
	return asm_safe("lidt %0", "m"(*ptr));
}

static inline int lidt_fep_safe(const struct descriptor_table_ptr *ptr)
{
	return asm_fep_safe("lidt %0", "m"(*ptr));
}

static inline void sidt(struct descriptor_table_ptr *ptr)
{
	asm volatile ("sidt %0" : "=m"(*ptr));
}

static inline void lldt(u16 val)
{
	asm volatile ("lldt %0" : : "rm"(val));
}

static inline int lldt_safe(u16 val)
{
	return asm_safe("lldt %0", "rm"(val));
}

static inline int lldt_fep_safe(u16 val)
{
	return asm_safe("lldt %0", "rm"(val));
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

static inline int ltr_safe(u16 val)
{
	return asm_safe("ltr %0", "rm"(val));
}

static inline int ltr_fep_safe(u16 val)
{
	return asm_safe("ltr %0", "rm"(val));
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

/*
 * See also safe_halt().
 */
static inline void sti(void)
{
	asm volatile ("sti");
}

/*
 * Enable interrupts and ensure that interrupts are evaluated upon return from
 * this function, i.e. execute a nop to consume the STi interrupt shadow.
 */
static inline void sti_nop(void)
{
	asm volatile ("sti; nop");
}

/*
 * Enable interrupts for one instruction (nop), to allow the CPU to process all
 * interrupts that are already pending.
 */
static inline void sti_nop_cli(void)
{
	asm volatile ("sti; nop; cli");
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


static inline void invlpg(volatile void *va)
{
	asm volatile("invlpg (%0)" ::"r" (va) : "memory");
}

struct invpcid_desc {
	u64 pcid : 12;
	u64 rsv  : 52;
	u64 addr : 64;
};

static inline int invpcid_safe(unsigned long type, struct invpcid_desc *desc)
{
	/* invpcid (%rax), %rbx */
	return asm_safe(".byte 0x66,0x0f,0x38,0x82,0x18", "a" (desc), "b" (type));
}

/*
 * Execute HLT in an STI interrupt shadow to ensure that a pending IRQ that's
 * intended to be a wake event arrives *after* HLT is executed.  Modern CPUs,
 * except for a few oddballs that KVM is unlikely to run on, block IRQs for one
 * instruction after STI, *if* RFLAGS.IF=0 before STI.  Note, Intel CPUs may
 * block other events beyond regular IRQs, e.g. may block NMIs and SMIs too.
 */
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
	int va_width, shift_amt;

	if (this_cpu_has_p(X86_PROPERTY_MAX_VIRT_ADDR))
		va_width = this_cpu_property(X86_PROPERTY_MAX_VIRT_ADDR);
	else
		va_width = 48;

	shift_amt = 64 - va_width;
	return (s64)(addr << shift_amt) >> shift_amt == addr;
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

static inline bool is_la57_enabled(void)
{
	return !!(read_cr4() & X86_CR4_LA57);
}

static inline bool is_lam_sup_enabled(void)
{
	return !!(read_cr4() & X86_CR4_LAM_SUP);
}

static inline bool is_lam_u48_enabled(void)
{
	return (read_cr3() & (X86_CR3_LAM_U48 | X86_CR3_LAM_U57)) == X86_CR3_LAM_U48;
}

static inline bool is_lam_u57_enabled(void)
{
	return !!(read_cr3() & X86_CR3_LAM_U57);
}

#endif
