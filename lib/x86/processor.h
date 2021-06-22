#ifndef _X86_PROCESSOR_H_
#define _X86_PROCESSOR_H_

#include "libcflat.h"
#include "desc.h"
#include "msr.h"
#include <stdint.h>

#define NONCANONICAL            0xaaaaaaaaaaaaaaaaull

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

#define X86_CR0_PE	0x00000001
#define X86_CR0_MP	0x00000002
#define X86_CR0_EM	0x00000004
#define X86_CR0_TS	0x00000008
#define X86_CR0_WP	0x00010000
#define X86_CR0_AM	0x00040000
#define X86_CR0_NW	0x20000000
#define X86_CR0_CD	0x40000000
#define X86_CR0_PG	0x80000000
#define X86_CR3_PCID_MASK 0x00000fff
#define X86_CR4_TSD	0x00000004
#define X86_CR4_DE	0x00000008
#define X86_CR4_PSE	0x00000010
#define X86_CR4_PAE	0x00000020
#define X86_CR4_MCE	0x00000040
#define X86_CR4_PGE	0x00000080
#define X86_CR4_PCE	0x00000100
#define X86_CR4_UMIP	0x00000800
#define X86_CR4_LA57	0x00001000
#define X86_CR4_VMXE	0x00002000
#define X86_CR4_PCIDE	0x00020000
#define X86_CR4_OSXSAVE	0x00040000
#define X86_CR4_SMEP	0x00100000
#define X86_CR4_SMAP	0x00200000
#define X86_CR4_PKE	0x00400000
#define X86_CR4_CET	0x00800000
#define X86_CR4_PKS	0x01000000

#define X86_EFLAGS_CF    0x00000001
#define X86_EFLAGS_FIXED 0x00000002
#define X86_EFLAGS_PF    0x00000004
#define X86_EFLAGS_AF    0x00000010
#define X86_EFLAGS_ZF    0x00000040
#define X86_EFLAGS_SF    0x00000080
#define X86_EFLAGS_TF    0x00000100
#define X86_EFLAGS_IF    0x00000200
#define X86_EFLAGS_DF    0x00000400
#define X86_EFLAGS_OF    0x00000800
#define X86_EFLAGS_IOPL  0x00003000
#define X86_EFLAGS_NT    0x00004000
#define X86_EFLAGS_VM    0x00020000
#define X86_EFLAGS_AC    0x00040000

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
#define	X86_FEATURE_SMEP	        (CPUID(0x7, 0, EBX, 7))
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
#define	X86_FEATURE_NRIPS		(CPUID(0x8000000A, 0, EDX, 3))


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

static inline void barrier(void)
{
    asm volatile ("" : : : "memory");
}

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

static inline int rdmsr_checking(u32 index)
{
	asm volatile (ASM_TRY("1f")
		      "rdmsr\n\t"
		      "1:"
		      : : "c"(index) : "memory", "eax", "edx");
	return exception_vector();
}

static inline int wrmsr_checking(u32 index, u64 val)
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

static inline void write_cr0(ulong val)
{
    asm volatile ("mov %0, %%cr0" : : "r"(val) : "memory");
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

static inline void write_cr3(ulong val)
{
    asm volatile ("mov %0, %%cr3" : : "r"(val) : "memory");
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

static inline void write_cr4(ulong val)
{
    asm volatile ("mov %0, %%cr4" : : "r"(val) : "memory");
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

static inline void lldt(unsigned val)
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
	unsigned a = tsc, d = tsc >> 32;

	asm volatile("wrmsr" : : "a"(a), "d"(d), "c"(0x10));
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
	return (s64)(addr << 16) >> 16 == addr;
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

static inline int has_spec_ctrl(void)
{
    return !!(this_cpu_has(X86_FEATURE_SPEC_CTRL));
}

static inline int cpu_has_efer_nx(void)
{
	return !!(this_cpu_has(X86_FEATURE_NX));
}

static inline bool cpuid_osxsave(void)
{
	return cpuid(1).c & (1 << (X86_FEATURE_OSXSAVE % 32));
}

#endif
