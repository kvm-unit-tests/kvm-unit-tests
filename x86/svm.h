#ifndef X86_SVM_H
#define X86_SVM_H

#include "libcflat.h"

enum {
	INTERCEPT_INTR,
	INTERCEPT_NMI,
	INTERCEPT_SMI,
	INTERCEPT_INIT,
	INTERCEPT_VINTR,
	INTERCEPT_SELECTIVE_CR0,
	INTERCEPT_STORE_IDTR,
	INTERCEPT_STORE_GDTR,
	INTERCEPT_STORE_LDTR,
	INTERCEPT_STORE_TR,
	INTERCEPT_LOAD_IDTR,
	INTERCEPT_LOAD_GDTR,
	INTERCEPT_LOAD_LDTR,
	INTERCEPT_LOAD_TR,
	INTERCEPT_RDTSC,
	INTERCEPT_RDPMC,
	INTERCEPT_PUSHF,
	INTERCEPT_POPF,
	INTERCEPT_CPUID,
	INTERCEPT_RSM,
	INTERCEPT_IRET,
	INTERCEPT_INTn,
	INTERCEPT_INVD,
	INTERCEPT_PAUSE,
	INTERCEPT_HLT,
	INTERCEPT_INVLPG,
	INTERCEPT_INVLPGA,
	INTERCEPT_IOIO_PROT,
	INTERCEPT_MSR_PROT,
	INTERCEPT_TASK_SWITCH,
	INTERCEPT_FERR_FREEZE,
	INTERCEPT_SHUTDOWN,
	INTERCEPT_VMRUN,
	INTERCEPT_VMMCALL,
	INTERCEPT_VMLOAD,
	INTERCEPT_VMSAVE,
	INTERCEPT_STGI,
	INTERCEPT_CLGI,
	INTERCEPT_SKINIT,
	INTERCEPT_RDTSCP,
	INTERCEPT_ICEBP,
	INTERCEPT_WBINVD,
	INTERCEPT_MONITOR,
	INTERCEPT_MWAIT,
	INTERCEPT_MWAIT_COND,
};

enum {
        VMCB_CLEAN_INTERCEPTS = 1, /* Intercept vectors, TSC offset, pause filter count */
        VMCB_CLEAN_PERM_MAP = 2,   /* IOPM Base and MSRPM Base */
        VMCB_CLEAN_ASID = 4,       /* ASID */
        VMCB_CLEAN_INTR = 8,       /* int_ctl, int_vector */
        VMCB_CLEAN_NPT = 16,       /* npt_en, nCR3, gPAT */
        VMCB_CLEAN_CR = 32,        /* CR0, CR3, CR4, EFER */
        VMCB_CLEAN_DR = 64,        /* DR6, DR7 */
        VMCB_CLEAN_DT = 128,       /* GDT, IDT */
        VMCB_CLEAN_SEG = 256,      /* CS, DS, SS, ES, CPL */
        VMCB_CLEAN_CR2 = 512,      /* CR2 only */
        VMCB_CLEAN_LBR = 1024,     /* DBGCTL, BR_FROM, BR_TO, LAST_EX_FROM, LAST_EX_TO */
        VMCB_CLEAN_AVIC = 2048,    /* APIC_BAR, APIC_BACKING_PAGE,
				      PHYSICAL_TABLE pointer, LOGICAL_TABLE pointer */
        VMCB_CLEAN_ALL = 4095,
};

struct __attribute__ ((__packed__)) vmcb_control_area {
	u16 intercept_cr_read;
	u16 intercept_cr_write;
	u16 intercept_dr_read;
	u16 intercept_dr_write;
	u32 intercept_exceptions;
	u64 intercept;
	u8 reserved_1[40];
	u16 pause_filter_thresh;
	u16 pause_filter_count;
	u64 iopm_base_pa;
	u64 msrpm_base_pa;
	u64 tsc_offset;
	u32 asid;
	u8 tlb_ctl;
	u8 reserved_2[3];
	u32 int_ctl;
	u32 int_vector;
	u32 int_state;
	u8 reserved_3[4];
	u32 exit_code;
	u32 exit_code_hi;
	u64 exit_info_1;
	u64 exit_info_2;
	u32 exit_int_info;
	u32 exit_int_info_err;
	u64 nested_ctl;
	u8 reserved_4[16];
	u32 event_inj;
	u32 event_inj_err;
	u64 nested_cr3;
	u64 virt_ext;
	u32 clean;
	u32 reserved_5;
	u64 next_rip;
	u8 insn_len;
	u8 insn_bytes[15];
	u8 reserved_6[800];
};

#define TLB_CONTROL_DO_NOTHING 0
#define TLB_CONTROL_FLUSH_ALL_ASID 1

#define V_TPR_MASK 0x0f

#define V_IRQ_SHIFT 8
#define V_IRQ_MASK (1 << V_IRQ_SHIFT)

#define V_GIF_ENABLED_SHIFT 25
#define V_GIF_ENABLED_MASK (1 << V_GIF_ENABLED_SHIFT)

#define V_GIF_SHIFT 9
#define V_GIF_MASK (1 << V_GIF_SHIFT)

#define V_INTR_PRIO_SHIFT 16
#define V_INTR_PRIO_MASK (0x0f << V_INTR_PRIO_SHIFT)

#define V_IGN_TPR_SHIFT 20
#define V_IGN_TPR_MASK (1 << V_IGN_TPR_SHIFT)

#define V_INTR_MASKING_SHIFT 24
#define V_INTR_MASKING_MASK (1 << V_INTR_MASKING_SHIFT)

#define V_NMI_PENDING_SHIFT	11
#define V_NMI_PENDING_MASK	(1 << V_NMI_PENDING_SHIFT)
#define V_NMI_BLOCKING_SHIFT	12
#define V_NMI_BLOCKING_MASK	(1 << V_NMI_BLOCKING_SHIFT)
#define V_NMI_ENABLE_SHIFT	26
#define V_NMI_ENABLE_MASK	(1 << V_NMI_ENABLE_SHIFT)

#define SVM_INTERRUPT_SHADOW_MASK 1

#define SVM_IOIO_STR_SHIFT 2
#define SVM_IOIO_REP_SHIFT 3
#define SVM_IOIO_SIZE_SHIFT 4
#define SVM_IOIO_ASIZE_SHIFT 7

#define SVM_IOIO_TYPE_MASK 1
#define SVM_IOIO_STR_MASK (1 << SVM_IOIO_STR_SHIFT)
#define SVM_IOIO_REP_MASK (1 << SVM_IOIO_REP_SHIFT)
#define SVM_IOIO_SIZE_MASK (7 << SVM_IOIO_SIZE_SHIFT)
#define SVM_IOIO_ASIZE_MASK (7 << SVM_IOIO_ASIZE_SHIFT)

#define SVM_VM_CR_VALID_MASK	0x001fULL
#define SVM_VM_CR_SVM_LOCK_MASK 0x0008ULL
#define SVM_VM_CR_SVM_DIS_MASK  0x0010ULL

#define TSC_RATIO_DEFAULT   0x0100000000ULL

struct __attribute__ ((__packed__)) vmcb_seg {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
};

struct __attribute__ ((__packed__)) vmcb_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	u8 reserved_1[43];
	u8 cpl;
	u8 reserved_2[4];
	u64 efer;
	u8 reserved_3[112];
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u8 reserved_4[88];
	u64 rsp;
	u8 reserved_5[24];
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_6[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
};

struct __attribute__ ((__packed__)) vmcb {
	struct vmcb_control_area control;
	struct vmcb_save_area save;
};

#define SVM_CPUID_FEATURE_SHIFT 2
#define SVM_CPUID_FUNC 0x8000000a

#define SVM_VM_CR_SVM_DISABLE 4

#define SVM_SELECTOR_S_SHIFT 4
#define SVM_SELECTOR_DPL_SHIFT 5
#define SVM_SELECTOR_P_SHIFT 7
#define SVM_SELECTOR_AVL_SHIFT 8
#define SVM_SELECTOR_L_SHIFT 9
#define SVM_SELECTOR_DB_SHIFT 10
#define SVM_SELECTOR_G_SHIFT 11

#define SVM_SELECTOR_TYPE_MASK (0xf)
#define SVM_SELECTOR_S_MASK (1 << SVM_SELECTOR_S_SHIFT)
#define SVM_SELECTOR_DPL_MASK (3 << SVM_SELECTOR_DPL_SHIFT)
#define SVM_SELECTOR_P_MASK (1 << SVM_SELECTOR_P_SHIFT)
#define SVM_SELECTOR_AVL_MASK (1 << SVM_SELECTOR_AVL_SHIFT)
#define SVM_SELECTOR_L_MASK (1 << SVM_SELECTOR_L_SHIFT)
#define SVM_SELECTOR_DB_MASK (1 << SVM_SELECTOR_DB_SHIFT)
#define SVM_SELECTOR_G_MASK (1 << SVM_SELECTOR_G_SHIFT)

#define SVM_SELECTOR_WRITE_MASK (1 << 1)
#define SVM_SELECTOR_READ_MASK SVM_SELECTOR_WRITE_MASK
#define SVM_SELECTOR_CODE_MASK (1 << 3)

#define INTERCEPT_CR0_MASK 1
#define INTERCEPT_CR3_MASK (1 << 3)
#define INTERCEPT_CR4_MASK (1 << 4)
#define INTERCEPT_CR8_MASK (1 << 8)

#define INTERCEPT_DR0_MASK 1
#define INTERCEPT_DR1_MASK (1 << 1)
#define INTERCEPT_DR2_MASK (1 << 2)
#define INTERCEPT_DR3_MASK (1 << 3)
#define INTERCEPT_DR4_MASK (1 << 4)
#define INTERCEPT_DR5_MASK (1 << 5)
#define INTERCEPT_DR6_MASK (1 << 6)
#define INTERCEPT_DR7_MASK (1 << 7)

#define SVM_EVTINJ_VEC_MASK 0xff

#define SVM_EVTINJ_TYPE_SHIFT 8
#define SVM_EVTINJ_TYPE_MASK (7 << SVM_EVTINJ_TYPE_SHIFT)

#define SVM_EVTINJ_TYPE_INTR (0 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI (2 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXEPT (3 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SOFT (4 << SVM_EVTINJ_TYPE_SHIFT)

#define SVM_EVTINJ_VALID (1 << 31)
#define SVM_EVTINJ_VALID_ERR (1 << 11)

#define SVM_EXITINTINFO_VEC_MASK SVM_EVTINJ_VEC_MASK
#define SVM_EXITINTINFO_TYPE_MASK SVM_EVTINJ_TYPE_MASK

#define	SVM_EXITINTINFO_TYPE_INTR SVM_EVTINJ_TYPE_INTR
#define	SVM_EXITINTINFO_TYPE_NMI SVM_EVTINJ_TYPE_NMI
#define	SVM_EXITINTINFO_TYPE_EXEPT SVM_EVTINJ_TYPE_EXEPT
#define	SVM_EXITINTINFO_TYPE_SOFT SVM_EVTINJ_TYPE_SOFT

#define SVM_EXITINTINFO_VALID SVM_EVTINJ_VALID
#define SVM_EXITINTINFO_VALID_ERR SVM_EVTINJ_VALID_ERR

#define SVM_EXITINFOSHIFT_TS_REASON_IRET 36
#define SVM_EXITINFOSHIFT_TS_REASON_JMP 38
#define SVM_EXITINFOSHIFT_TS_HAS_ERROR_CODE 44

#define	SVM_EXIT_READ_CR0 	0x000
#define	SVM_EXIT_READ_CR3 	0x003
#define	SVM_EXIT_READ_CR4 	0x004
#define	SVM_EXIT_READ_CR8 	0x008
#define	SVM_EXIT_WRITE_CR0 	0x010
#define	SVM_EXIT_WRITE_CR3 	0x013
#define	SVM_EXIT_WRITE_CR4 	0x014
#define	SVM_EXIT_WRITE_CR8 	0x018
#define	SVM_EXIT_READ_DR0 	0x020
#define	SVM_EXIT_READ_DR1 	0x021
#define	SVM_EXIT_READ_DR2 	0x022
#define	SVM_EXIT_READ_DR3 	0x023
#define	SVM_EXIT_READ_DR4 	0x024
#define	SVM_EXIT_READ_DR5 	0x025
#define	SVM_EXIT_READ_DR6 	0x026
#define	SVM_EXIT_READ_DR7 	0x027
#define	SVM_EXIT_WRITE_DR0 	0x030
#define	SVM_EXIT_WRITE_DR1 	0x031
#define	SVM_EXIT_WRITE_DR2 	0x032
#define	SVM_EXIT_WRITE_DR3 	0x033
#define	SVM_EXIT_WRITE_DR4 	0x034
#define	SVM_EXIT_WRITE_DR5 	0x035
#define	SVM_EXIT_WRITE_DR6 	0x036
#define	SVM_EXIT_WRITE_DR7 	0x037
#define SVM_EXIT_EXCP_BASE      0x040
#define SVM_EXIT_INTR		0x060
#define SVM_EXIT_NMI		0x061
#define SVM_EXIT_SMI		0x062
#define SVM_EXIT_INIT		0x063
#define SVM_EXIT_VINTR		0x064
#define SVM_EXIT_CR0_SEL_WRITE	0x065
#define SVM_EXIT_IDTR_READ	0x066
#define SVM_EXIT_GDTR_READ	0x067
#define SVM_EXIT_LDTR_READ	0x068
#define SVM_EXIT_TR_READ	0x069
#define SVM_EXIT_IDTR_WRITE	0x06a
#define SVM_EXIT_GDTR_WRITE	0x06b
#define SVM_EXIT_LDTR_WRITE	0x06c
#define SVM_EXIT_TR_WRITE	0x06d
#define SVM_EXIT_RDTSC		0x06e
#define SVM_EXIT_RDPMC		0x06f
#define SVM_EXIT_PUSHF		0x070
#define SVM_EXIT_POPF		0x071
#define SVM_EXIT_CPUID		0x072
#define SVM_EXIT_RSM		0x073
#define SVM_EXIT_IRET		0x074
#define SVM_EXIT_SWINT		0x075
#define SVM_EXIT_INVD		0x076
#define SVM_EXIT_PAUSE		0x077
#define SVM_EXIT_HLT		0x078
#define SVM_EXIT_INVLPG		0x079
#define SVM_EXIT_INVLPGA	0x07a
#define SVM_EXIT_IOIO		0x07b
#define SVM_EXIT_MSR		0x07c
#define SVM_EXIT_TASK_SWITCH	0x07d
#define SVM_EXIT_FERR_FREEZE	0x07e
#define SVM_EXIT_SHUTDOWN	0x07f
#define SVM_EXIT_VMRUN		0x080
#define SVM_EXIT_VMMCALL	0x081
#define SVM_EXIT_VMLOAD		0x082
#define SVM_EXIT_VMSAVE		0x083
#define SVM_EXIT_STGI		0x084
#define SVM_EXIT_CLGI		0x085
#define SVM_EXIT_SKINIT		0x086
#define SVM_EXIT_RDTSCP		0x087
#define SVM_EXIT_ICEBP		0x088
#define SVM_EXIT_WBINVD		0x089
#define SVM_EXIT_MONITOR	0x08a
#define SVM_EXIT_MWAIT		0x08b
#define SVM_EXIT_MWAIT_COND	0x08c
#define SVM_EXIT_NPF  		0x400

#define SVM_EXIT_ERR		-1

#define SVM_CR0_SELECTIVE_MASK (X86_CR0_TS | X86_CR0_MP)

#define	SVM_CR0_RESERVED_MASK			0xffffffff00000000U
#define	SVM_CR3_LONG_MBZ_MASK			0xfff0000000000000U
#define	SVM_CR3_LONG_RESERVED_MASK		0x0000000000000fe7U
#define SVM_CR3_PAE_LEGACY_RESERVED_MASK	0x0000000000000007U
#define	SVM_CR4_LEGACY_RESERVED_MASK		0xff08e000U
#define	SVM_CR4_RESERVED_MASK			0xffffffffff08e000U
#define	SVM_DR6_RESERVED_MASK			0xffffffffffff1ff0U
#define	SVM_DR7_RESERVED_MASK			0xffffffff0000cc00U
#define	SVM_EFER_RESERVED_MASK			0xffffffffffff0200U

#define MSR_BITMAP_SIZE 8192

#define LBR_CTL_ENABLE_MASK BIT_ULL(0)

struct svm_test {
	const char *name;
	bool (*supported)(void);
	void (*prepare)(struct svm_test *test);
	void (*prepare_gif_clear)(struct svm_test *test);
	void (*guest_func)(struct svm_test *test);
	bool (*finished)(struct svm_test *test);
	bool (*succeeded)(struct svm_test *test);
	int exits;
	ulong scratch;
	/* Alternative test interface. */
	void (*v2)(void);
	int on_vcpu;
	bool on_vcpu_done;
};

struct regs {
	u64 rax;
	u64 rbx;
	u64 rcx;
	u64 rdx;
	u64 cr2;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rflags;
};

typedef void (*test_guest_func)(struct svm_test *);

int run_svm_tests(int ac, char **av, struct svm_test *svm_tests);
u64 *npt_get_pte(u64 address);
u64 *npt_get_pde(u64 address);
u64 *npt_get_pdpe(u64 address);
u64 *npt_get_pml4e(void);
bool smp_supported(void);
bool default_supported(void);
bool vgif_supported(void);
bool lbrv_supported(void);
bool tsc_scale_supported(void);
bool pause_filter_supported(void);
bool pause_threshold_supported(void);
void default_prepare(struct svm_test *test);
void default_prepare_gif_clear(struct svm_test *test);
bool default_finished(struct svm_test *test);
bool npt_supported(void);
bool vnmi_supported(void);
int get_test_stage(struct svm_test *test);
void set_test_stage(struct svm_test *test, int s);
void inc_test_stage(struct svm_test *test);
void vmcb_ident(struct vmcb *vmcb);
struct regs get_regs(void);
void vmmcall(void);
int __svm_vmrun(u64 rip);
void __svm_bare_vmrun(void);
int svm_vmrun(void);
void test_set_guest(test_guest_func func);
u64* get_npt_pte(u64 *pml4, u64 guest_addr, int level);

extern struct vmcb *vmcb;

static inline void stgi(void)
{
    asm volatile ("stgi");
}

static inline void clgi(void)
{
    asm volatile ("clgi");
}



#define SAVE_GPR_C                              \
        "xchg %%rbx, regs+0x8\n\t"              \
        "xchg %%rcx, regs+0x10\n\t"             \
        "xchg %%rdx, regs+0x18\n\t"             \
        "xchg %%rbp, regs+0x28\n\t"             \
        "xchg %%rsi, regs+0x30\n\t"             \
        "xchg %%rdi, regs+0x38\n\t"             \
        "xchg %%r8, regs+0x40\n\t"              \
        "xchg %%r9, regs+0x48\n\t"              \
        "xchg %%r10, regs+0x50\n\t"             \
        "xchg %%r11, regs+0x58\n\t"             \
        "xchg %%r12, regs+0x60\n\t"             \
        "xchg %%r13, regs+0x68\n\t"             \
        "xchg %%r14, regs+0x70\n\t"             \
        "xchg %%r15, regs+0x78\n\t"

#define LOAD_GPR_C      SAVE_GPR_C

#define ASM_PRE_VMRUN_CMD                       \
                "vmload %%rax\n\t"              \
                "mov regs+0x80, %%r15\n\t"      \
                "mov %%r15, 0x170(%%rax)\n\t"   \
                "mov regs, %%r15\n\t"           \
                "mov %%r15, 0x1f8(%%rax)\n\t"   \
                LOAD_GPR_C                      \

#define ASM_POST_VMRUN_CMD                      \
                SAVE_GPR_C                      \
                "mov 0x170(%%rax), %%r15\n\t"   \
                "mov %%r15, regs+0x80\n\t"      \
                "mov 0x1f8(%%rax), %%r15\n\t"   \
                "mov %%r15, regs\n\t"           \
                "vmsave %%rax\n\t"              \



#define SVM_BARE_VMRUN \
	asm volatile ( \
		ASM_PRE_VMRUN_CMD \
                "vmrun %%rax\n\t"               \
		ASM_POST_VMRUN_CMD \
		: \
		: "a" (virt_to_phys(vmcb)) \
		: "memory", "r15") \

#endif
