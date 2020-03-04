#include "svm.h"
#include "libcflat.h"
#include "processor.h"
#include "desc.h"
#include "msr.h"
#include "vm.h"
#include "smp.h"
#include "types.h"
#include "alloc_page.h"
#include "isr.h"
#include "apic.h"

#define SVM_EXIT_MAX_DR_INTERCEPT 0x3f

/* for the nested page table*/
u64 *pml4e;
u64 *pdpe;
u64 *pde[4];
u64 *pte[2048];
void *scratch_page;

#define LATENCY_RUNS 1000000

u64 tsc_start;
u64 tsc_end;

u64 vmrun_sum, vmexit_sum;
u64 vmsave_sum, vmload_sum;
u64 stgi_sum, clgi_sum;
u64 latvmrun_max;
u64 latvmrun_min;
u64 latvmexit_max;
u64 latvmexit_min;
u64 latvmload_max;
u64 latvmload_min;
u64 latvmsave_max;
u64 latvmsave_min;
u64 latstgi_max;
u64 latstgi_min;
u64 latclgi_max;
u64 latclgi_min;
u64 runs;

u8 *io_bitmap;
u8 io_bitmap_area[16384];

#define MSR_BITMAP_SIZE 8192

u8 *msr_bitmap;
u8 msr_bitmap_area[MSR_BITMAP_SIZE + PAGE_SIZE];

static bool npt_supported(void)
{
	return this_cpu_has(X86_FEATURE_NPT);
}

static void setup_svm(void)
{
    void *hsave = alloc_page();
    u64 *page, address;
    int i,j;

    wrmsr(MSR_VM_HSAVE_PA, virt_to_phys(hsave));
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SVME);
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_NX);

    scratch_page = alloc_page();

    io_bitmap = (void *) (((ulong)io_bitmap_area + 4095) & ~4095);

    msr_bitmap = (void *) ALIGN((ulong)msr_bitmap_area, PAGE_SIZE);

    if (!npt_supported())
        return;

    printf("NPT detected - running all tests with NPT enabled\n");

    /*
     * Nested paging supported - Build a nested page table
     * Build the page-table bottom-up and map everything with 4k pages
     * to get enough granularity for the NPT unit-tests.
     */

    address = 0;

    /* PTE level */
    for (i = 0; i < 2048; ++i) {
        page = alloc_page();

        for (j = 0; j < 512; ++j, address += 4096)
            page[j] = address | 0x067ULL;

        pte[i] = page;
    }

    /* PDE level */
    for (i = 0; i < 4; ++i) {
        page = alloc_page();

        for (j = 0; j < 512; ++j)
            page[j] = (u64)pte[(i * 512) + j] | 0x027ULL;

        pde[i] = page;
    }

    /* PDPe level */
    pdpe   = alloc_page();
    for (i = 0; i < 4; ++i)
       pdpe[i] = ((u64)(pde[i])) | 0x27;

    /* PML4e level */
    pml4e    = alloc_page();
    pml4e[0] = ((u64)pdpe) | 0x27;
}

static u64 *npt_get_pde(u64 address)
{
    int i1, i2;

    address >>= 21;
    i1 = (address >> 9) & 0x3;
    i2 = address & 0x1ff;

    return &pde[i1][i2];
}

static u64 *npt_get_pte(u64 address)
{
    int i1, i2;

    address >>= 12;
    i1 = (address >> 9) & 0x7ff;
    i2 = address & 0x1ff;

    return &pte[i1][i2];
}

static void vmcb_set_seg(struct vmcb_seg *seg, u16 selector,
                         u64 base, u32 limit, u32 attr)
{
    seg->selector = selector;
    seg->attrib = attr;
    seg->limit = limit;
    seg->base = base;
}

static void vmcb_ident(struct vmcb *vmcb)
{
    u64 vmcb_phys = virt_to_phys(vmcb);
    struct vmcb_save_area *save = &vmcb->save;
    struct vmcb_control_area *ctrl = &vmcb->control;
    u32 data_seg_attr = 3 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
        | SVM_SELECTOR_DB_MASK | SVM_SELECTOR_G_MASK;
    u32 code_seg_attr = 9 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
        | SVM_SELECTOR_L_MASK | SVM_SELECTOR_G_MASK;
    struct descriptor_table_ptr desc_table_ptr;

    memset(vmcb, 0, sizeof(*vmcb));
    asm volatile ("vmsave %0" : : "a"(vmcb_phys) : "memory");
    vmcb_set_seg(&save->es, read_es(), 0, -1U, data_seg_attr);
    vmcb_set_seg(&save->cs, read_cs(), 0, -1U, code_seg_attr);
    vmcb_set_seg(&save->ss, read_ss(), 0, -1U, data_seg_attr);
    vmcb_set_seg(&save->ds, read_ds(), 0, -1U, data_seg_attr);
    sgdt(&desc_table_ptr);
    vmcb_set_seg(&save->gdtr, 0, desc_table_ptr.base, desc_table_ptr.limit, 0);
    sidt(&desc_table_ptr);
    vmcb_set_seg(&save->idtr, 0, desc_table_ptr.base, desc_table_ptr.limit, 0);
    ctrl->asid = 1;
    save->cpl = 0;
    save->efer = rdmsr(MSR_EFER);
    save->cr4 = read_cr4();
    save->cr3 = read_cr3();
    save->cr0 = read_cr0();
    save->dr7 = read_dr7();
    save->dr6 = read_dr6();
    save->cr2 = read_cr2();
    save->g_pat = rdmsr(MSR_IA32_CR_PAT);
    save->dbgctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
    ctrl->intercept = (1ULL << INTERCEPT_VMRUN) | (1ULL << INTERCEPT_VMMCALL);
    ctrl->iopm_base_pa = virt_to_phys(io_bitmap);
    ctrl->msrpm_base_pa = virt_to_phys(msr_bitmap);

    if (npt_supported()) {
        ctrl->nested_ctl = 1;
        ctrl->nested_cr3 = (u64)pml4e;
    }
}

struct test {
    const char *name;
    bool (*supported)(void);
    void (*prepare)(struct test *test);
    void (*prepare_gif_clear)(struct test *test);
    void (*guest_func)(struct test *test);
    bool (*finished)(struct test *test);
    bool (*succeeded)(struct test *test);
    struct vmcb *vmcb;
    int exits;
    ulong scratch;
};

static inline void vmmcall(void)
{
    asm volatile ("vmmcall" : : : "memory");
}

static void test_thunk(struct test *test)
{
    test->guest_func(test);
    vmmcall();
}

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

struct regs regs;

// rax handled specially below

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

static void test_run(struct test *test, struct vmcb *vmcb)
{
    u64 vmcb_phys = virt_to_phys(vmcb);
    u64 guest_stack[10000];

    irq_disable();
    test->vmcb = vmcb;
    test->prepare(test);
    vmcb->save.rip = (ulong)test_thunk;
    vmcb->save.rsp = (ulong)(guest_stack + ARRAY_SIZE(guest_stack));
    regs.rdi = (ulong)test;
    do {
        struct test *the_test = test;
        u64 the_vmcb = vmcb_phys;
        tsc_start = rdtsc();
        asm volatile (
            "clgi;\n\t" // semi-colon needed for LLVM compatibility
            "sti \n\t"
            "call *%c[PREPARE_GIF_CLEAR](%[test]) \n \t"
            "mov %[vmcb_phys], %%rax \n\t"
            "vmload %%rax\n\t"
            "mov regs+0x80, %%r15\n\t"  // rflags
            "mov %%r15, 0x170(%%rax)\n\t"
            "mov regs, %%r15\n\t"       // rax
            "mov %%r15, 0x1f8(%%rax)\n\t"
            LOAD_GPR_C
            "vmrun %%rax\n\t"
            SAVE_GPR_C
            "mov 0x170(%%rax), %%r15\n\t"  // rflags
            "mov %%r15, regs+0x80\n\t"
            "mov 0x1f8(%%rax), %%r15\n\t"  // rax
            "mov %%r15, regs\n\t"
            "vmsave %%rax\n\t"
            "cli \n\t"
            "stgi"
            : // inputs clobbered by the guest:
	      "=D" (the_test),            // first argument register
	      "=b" (the_vmcb)             // callee save register!
            : [test] "0" (the_test),
	      [vmcb_phys] "1"(the_vmcb),
	      [PREPARE_GIF_CLEAR] "i" (offsetof(struct test, prepare_gif_clear))
            : "rax", "rcx", "rdx", "rsi",
              "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15",
              "memory");
	tsc_end = rdtsc();
        ++test->exits;
    } while (!test->finished(test));
    irq_enable();

    report(test->succeeded(test), "%s", test->name);
}

static bool smp_supported(void)
{
	return cpu_count() > 1;
}

static bool default_supported(void)
{
    return true;
}

static void default_prepare(struct test *test)
{
    vmcb_ident(test->vmcb);
}

static void default_prepare_gif_clear(struct test *test)
{
}

static bool default_finished(struct test *test)
{
    return true; /* one vmexit */
}

static void null_test(struct test *test)
{
}

static bool null_check(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_VMMCALL;
}

static void prepare_no_vmrun_int(struct test *test)
{
    test->vmcb->control.intercept &= ~(1ULL << INTERCEPT_VMRUN);
}

static bool check_no_vmrun_int(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_ERR;
}

static void test_vmrun(struct test *test)
{
    asm volatile ("vmrun %0" : : "a"(virt_to_phys(test->vmcb)));
}

static bool check_vmrun(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_VMRUN;
}

static void prepare_cr3_intercept(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.intercept_cr_read |= 1 << 3;
}

static void test_cr3_intercept(struct test *test)
{
    asm volatile ("mov %%cr3, %0" : "=r"(test->scratch) : : "memory");
}

static bool check_cr3_intercept(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_READ_CR3;
}

static bool check_cr3_nointercept(struct test *test)
{
    return null_check(test) && test->scratch == read_cr3();
}

static void corrupt_cr3_intercept_bypass(void *_test)
{
    struct test *test = _test;
    extern volatile u32 mmio_insn;

    while (!__sync_bool_compare_and_swap(&test->scratch, 1, 2))
        pause();
    pause();
    pause();
    pause();
    mmio_insn = 0x90d8200f;  // mov %cr3, %rax; nop
}

static void prepare_cr3_intercept_bypass(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.intercept_cr_read |= 1 << 3;
    on_cpu_async(1, corrupt_cr3_intercept_bypass, test);
}

static void test_cr3_intercept_bypass(struct test *test)
{
    ulong a = 0xa0000;

    test->scratch = 1;
    while (test->scratch != 2)
        barrier();

    asm volatile ("mmio_insn: mov %0, (%0); nop"
                  : "+a"(a) : : "memory");
    test->scratch = a;
}

static void prepare_dr_intercept(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.intercept_dr_read = 0xff;
    test->vmcb->control.intercept_dr_write = 0xff;
}

static void test_dr_intercept(struct test *test)
{
    unsigned int i, failcnt = 0;

    /* Loop testing debug register reads */
    for (i = 0; i < 8; i++) {

        switch (i) {
        case 0:
            asm volatile ("mov %%dr0, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 1:
            asm volatile ("mov %%dr1, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 2:
            asm volatile ("mov %%dr2, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 3:
            asm volatile ("mov %%dr3, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 4:
            asm volatile ("mov %%dr4, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 5:
            asm volatile ("mov %%dr5, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 6:
            asm volatile ("mov %%dr6, %0" : "=r"(test->scratch) : : "memory");
            break;
        case 7:
            asm volatile ("mov %%dr7, %0" : "=r"(test->scratch) : : "memory");
            break;
        }

        if (test->scratch != i) {
            report(false, "dr%u read intercept", i);
            failcnt++;
        }
    }

    /* Loop testing debug register writes */
    for (i = 0; i < 8; i++) {

        switch (i) {
        case 0:
            asm volatile ("mov %0, %%dr0" : : "r"(test->scratch) : "memory");
            break;
        case 1:
            asm volatile ("mov %0, %%dr1" : : "r"(test->scratch) : "memory");
            break;
        case 2:
            asm volatile ("mov %0, %%dr2" : : "r"(test->scratch) : "memory");
            break;
        case 3:
            asm volatile ("mov %0, %%dr3" : : "r"(test->scratch) : "memory");
            break;
        case 4:
            asm volatile ("mov %0, %%dr4" : : "r"(test->scratch) : "memory");
            break;
        case 5:
            asm volatile ("mov %0, %%dr5" : : "r"(test->scratch) : "memory");
            break;
        case 6:
            asm volatile ("mov %0, %%dr6" : : "r"(test->scratch) : "memory");
            break;
        case 7:
            asm volatile ("mov %0, %%dr7" : : "r"(test->scratch) : "memory");
            break;
        }

        if (test->scratch != i) {
            report(false, "dr%u write intercept", i);
            failcnt++;
        }
    }

    test->scratch = failcnt;
}

static bool dr_intercept_finished(struct test *test)
{
    ulong n = (test->vmcb->control.exit_code - SVM_EXIT_READ_DR0);

    /* Only expect DR intercepts */
    if (n > (SVM_EXIT_MAX_DR_INTERCEPT - SVM_EXIT_READ_DR0))
        return true;

    /*
     * Compute debug register number.
     * Per Appendix C "SVM Intercept Exit Codes" of AMD64 Architecture
     * Programmer's Manual Volume 2 - System Programming:
     * http://support.amd.com/TechDocs/24593.pdf
     * there are 16 VMEXIT codes each for DR read and write.
     */
    test->scratch = (n % 16);

    /* Jump over MOV instruction */
    test->vmcb->save.rip += 3;

    return false;
}

static bool check_dr_intercept(struct test *test)
{
    return !test->scratch;
}

static bool next_rip_supported(void)
{
    return this_cpu_has(X86_FEATURE_NRIPS);
}

static void prepare_next_rip(struct test *test)
{
    test->vmcb->control.intercept |= (1ULL << INTERCEPT_RDTSC);
}


static void test_next_rip(struct test *test)
{
    asm volatile ("rdtsc\n\t"
                  ".globl exp_next_rip\n\t"
                  "exp_next_rip:\n\t" ::: "eax", "edx");
}

static bool check_next_rip(struct test *test)
{
    extern char exp_next_rip;
    unsigned long address = (unsigned long)&exp_next_rip;

    return address == test->vmcb->control.next_rip;
}

static void prepare_msr_intercept(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.intercept |= (1ULL << INTERCEPT_MSR_PROT);
    test->vmcb->control.intercept_exceptions |= (1ULL << GP_VECTOR);
    memset(msr_bitmap, 0xff, MSR_BITMAP_SIZE);
}

static void test_msr_intercept(struct test *test)
{
    unsigned long msr_value = 0xef8056791234abcd; /* Arbitrary value */
    unsigned long msr_index;

    for (msr_index = 0; msr_index <= 0xc0011fff; msr_index++) {
        if (msr_index == 0xC0010131 /* MSR_SEV_STATUS */) {
            /*
             * Per section 15.34.10 "SEV_STATUS MSR" of AMD64 Architecture
             * Programmer's Manual volume 2 - System Programming:
             * http://support.amd.com/TechDocs/24593.pdf
             * SEV_STATUS MSR (C001_0131) is a non-interceptable MSR.
             */
            continue;
        }

        /* Skips gaps between supported MSR ranges */
        if (msr_index == 0x2000)
            msr_index = 0xc0000000;
        else if (msr_index == 0xc0002000)
            msr_index = 0xc0010000;

        test->scratch = -1;

        rdmsr(msr_index);

        /* Check that a read intercept occurred for MSR at msr_index */
        if (test->scratch != msr_index)
            report(false, "MSR 0x%lx read intercept", msr_index);

        /*
         * Poor man approach to generate a value that
         * seems arbitrary each time around the loop.
         */
        msr_value += (msr_value << 1);

        wrmsr(msr_index, msr_value);

        /* Check that a write intercept occurred for MSR with msr_value */
        if (test->scratch != msr_value)
            report(false, "MSR 0x%lx write intercept", msr_index);
    }

    test->scratch = -2;
}

static bool msr_intercept_finished(struct test *test)
{
    u32 exit_code = test->vmcb->control.exit_code;
    u64 exit_info_1;
    u8 *opcode;

    if (exit_code == SVM_EXIT_MSR) {
        exit_info_1 = test->vmcb->control.exit_info_1;
    } else {
        /*
         * If #GP exception occurs instead, check that it was
         * for RDMSR/WRMSR and set exit_info_1 accordingly.
         */

        if (exit_code != (SVM_EXIT_EXCP_BASE + GP_VECTOR))
            return true;

        opcode = (u8 *)test->vmcb->save.rip;
        if (opcode[0] != 0x0f)
            return true;

        switch (opcode[1]) {
        case 0x30: /* WRMSR */
            exit_info_1 = 1;
            break;
        case 0x32: /* RDMSR */
            exit_info_1 = 0;
            break;
        default:
            return true;
        }

        /*
         * Warn that #GP exception occured instead.
         * RCX holds the MSR index.
         */
        printf("%s 0x%lx #GP exception\n",
            exit_info_1 ? "WRMSR" : "RDMSR", regs.rcx);
    }

    /* Jump over RDMSR/WRMSR instruction */
    test->vmcb->save.rip += 2;

    /*
     * Test whether the intercept was for RDMSR/WRMSR.
     * For RDMSR, test->scratch is set to the MSR index;
     *      RCX holds the MSR index.
     * For WRMSR, test->scratch is set to the MSR value;
     *      RDX holds the upper 32 bits of the MSR value,
     *      while RAX hold its lower 32 bits.
     */
    if (exit_info_1)
        test->scratch =
            ((regs.rdx << 32) | (test->vmcb->save.rax & 0xffffffff));
    else
        test->scratch = regs.rcx;

    return false;
}

static bool check_msr_intercept(struct test *test)
{
    memset(msr_bitmap, 0, MSR_BITMAP_SIZE);
    return (test->scratch == -2);
}

static void prepare_mode_switch(struct test *test)
{
    test->vmcb->control.intercept_exceptions |= (1ULL << GP_VECTOR)
                                             |  (1ULL << UD_VECTOR)
                                             |  (1ULL << DF_VECTOR)
                                             |  (1ULL << PF_VECTOR);
    test->scratch = 0;
}

static void test_mode_switch(struct test *test)
{
    asm volatile("	cli\n"
		 "	ljmp *1f\n" /* jump to 32-bit code segment */
		 "1:\n"
		 "	.long 2f\n"
		 "	.long " xstr(KERNEL_CS32) "\n"
		 ".code32\n"
		 "2:\n"
		 "	movl %%cr0, %%eax\n"
		 "	btcl  $31, %%eax\n" /* clear PG */
		 "	movl %%eax, %%cr0\n"
		 "	movl $0xc0000080, %%ecx\n" /* EFER */
		 "	rdmsr\n"
		 "	btcl $8, %%eax\n" /* clear LME */
		 "	wrmsr\n"
		 "	movl %%cr4, %%eax\n"
		 "	btcl $5, %%eax\n" /* clear PAE */
		 "	movl %%eax, %%cr4\n"
		 "	movw %[ds16], %%ax\n"
		 "	movw %%ax, %%ds\n"
		 "	ljmpl %[cs16], $3f\n" /* jump to 16 bit protected-mode */
		 ".code16\n"
		 "3:\n"
		 "	movl %%cr0, %%eax\n"
		 "	btcl $0, %%eax\n" /* clear PE  */
		 "	movl %%eax, %%cr0\n"
		 "	ljmpl $0, $4f\n"   /* jump to real-mode */
		 "4:\n"
		 "	vmmcall\n"
		 "	movl %%cr0, %%eax\n"
		 "	btsl $0, %%eax\n" /* set PE  */
		 "	movl %%eax, %%cr0\n"
		 "	ljmpl %[cs32], $5f\n" /* back to protected mode */
		 ".code32\n"
		 "5:\n"
		 "	movl %%cr4, %%eax\n"
		 "	btsl $5, %%eax\n" /* set PAE */
		 "	movl %%eax, %%cr4\n"
		 "	movl $0xc0000080, %%ecx\n" /* EFER */
		 "	rdmsr\n"
		 "	btsl $8, %%eax\n" /* set LME */
		 "	wrmsr\n"
		 "	movl %%cr0, %%eax\n"
		 "	btsl  $31, %%eax\n" /* set PG */
		 "	movl %%eax, %%cr0\n"
		 "	ljmpl %[cs64], $6f\n"    /* back to long mode */
		 ".code64\n\t"
		 "6:\n"
		 "	vmmcall\n"
		 :: [cs16] "i"(KERNEL_CS16), [ds16] "i"(KERNEL_DS16),
		    [cs32] "i"(KERNEL_CS32), [cs64] "i"(KERNEL_CS64)
		 : "rax", "rbx", "rcx", "rdx", "memory");
}

static bool mode_switch_finished(struct test *test)
{
    u64 cr0, cr4, efer;

    cr0  = test->vmcb->save.cr0;
    cr4  = test->vmcb->save.cr4;
    efer = test->vmcb->save.efer;

    /* Only expect VMMCALL intercepts */
    if (test->vmcb->control.exit_code != SVM_EXIT_VMMCALL)
	    return true;

    /* Jump over VMMCALL instruction */
    test->vmcb->save.rip += 3;

    /* Do sanity checks */
    switch (test->scratch) {
    case 0:
        /* Test should be in real mode now - check for this */
        if ((cr0  & 0x80000001) || /* CR0.PG, CR0.PE */
            (cr4  & 0x00000020) || /* CR4.PAE */
            (efer & 0x00000500))   /* EFER.LMA, EFER.LME */
                return true;
        break;
    case 2:
        /* Test should be back in long-mode now - check for this */
        if (((cr0  & 0x80000001) != 0x80000001) || /* CR0.PG, CR0.PE */
            ((cr4  & 0x00000020) != 0x00000020) || /* CR4.PAE */
            ((efer & 0x00000500) != 0x00000500))   /* EFER.LMA, EFER.LME */
		    return true;
	break;
    }

    /* one step forward */
    test->scratch += 1;

    return test->scratch == 2;
}

static bool check_mode_switch(struct test *test)
{
	return test->scratch == 2;
}

static void prepare_ioio(struct test *test)
{
    test->vmcb->control.intercept |= (1ULL << INTERCEPT_IOIO_PROT);
    test->scratch = 0;
    memset(io_bitmap, 0, 8192);
    io_bitmap[8192] = 0xFF;
}

static int get_test_stage(struct test *test)
{
    barrier();
    return test->scratch;
}

static void set_test_stage(struct test *test, int s)
{
    barrier();
    test->scratch = s;
    barrier();
}

static void inc_test_stage(struct test *test)
{
    barrier();
    test->scratch++;
    barrier();
}

static void test_ioio(struct test *test)
{
    // stage 0, test IO pass
    inb(0x5000);
    outb(0x0, 0x5000);
    if (get_test_stage(test) != 0)
        goto fail;

    // test IO width, in/out
    io_bitmap[0] = 0xFF;
    inc_test_stage(test);
    inb(0x0);
    if (get_test_stage(test) != 2)
        goto fail;

    outw(0x0, 0x0);
    if (get_test_stage(test) != 3)
        goto fail;

    inl(0x0);
    if (get_test_stage(test) != 4)
        goto fail;

    // test low/high IO port
    io_bitmap[0x5000 / 8] = (1 << (0x5000 % 8));
    inb(0x5000);
    if (get_test_stage(test) != 5)
        goto fail;

    io_bitmap[0x9000 / 8] = (1 << (0x9000 % 8));
    inw(0x9000);
    if (get_test_stage(test) != 6)
        goto fail;

    // test partial pass
    io_bitmap[0x5000 / 8] = (1 << (0x5000 % 8));
    inl(0x4FFF);
    if (get_test_stage(test) != 7)
        goto fail;

    // test across pages
    inc_test_stage(test);
    inl(0x7FFF);
    if (get_test_stage(test) != 8)
        goto fail;

    inc_test_stage(test);
    io_bitmap[0x8000 / 8] = 1 << (0x8000 % 8);
    inl(0x7FFF);
    if (get_test_stage(test) != 10)
        goto fail;

    io_bitmap[0] = 0;
    inl(0xFFFF);
    if (get_test_stage(test) != 11)
        goto fail;

    io_bitmap[0] = 0xFF;
    io_bitmap[8192] = 0;
    inl(0xFFFF);
    inc_test_stage(test);
    if (get_test_stage(test) != 12)
        goto fail;

    return;

fail:
    report(false, "stage %d", get_test_stage(test));
    test->scratch = -1;
}

static bool ioio_finished(struct test *test)
{
    unsigned port, size;

    /* Only expect IOIO intercepts */
    if (test->vmcb->control.exit_code == SVM_EXIT_VMMCALL)
        return true;

    if (test->vmcb->control.exit_code != SVM_EXIT_IOIO)
        return true;

    /* one step forward */
    test->scratch += 1;

    port = test->vmcb->control.exit_info_1 >> 16;
    size = (test->vmcb->control.exit_info_1 >> SVM_IOIO_SIZE_SHIFT) & 7;

    while (size--) {
        io_bitmap[port / 8] &= ~(1 << (port & 7));
        port++;
    }

    return false;
}

static bool check_ioio(struct test *test)
{
    memset(io_bitmap, 0, 8193);
    return test->scratch != -1;
}

static void prepare_asid_zero(struct test *test)
{
    test->vmcb->control.asid = 0;
}

static void test_asid_zero(struct test *test)
{
    asm volatile ("vmmcall\n\t");
}

static bool check_asid_zero(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_ERR;
}

static void sel_cr0_bug_prepare(struct test *test)
{
    vmcb_ident(test->vmcb);
    test->vmcb->control.intercept |= (1ULL << INTERCEPT_SELECTIVE_CR0);
}

static bool sel_cr0_bug_finished(struct test *test)
{
	return true;
}

static void sel_cr0_bug_test(struct test *test)
{
    unsigned long cr0;

    /* read cr0, clear CD, and write back */
    cr0  = read_cr0();
    cr0 |= (1UL << 30);
    write_cr0(cr0);

    /*
     * If we are here the test failed, not sure what to do now because we
     * are not in guest-mode anymore so we can't trigger an intercept.
     * Trigger a tripple-fault for now.
     */
    report(false, "sel_cr0 test. Can not recover from this - exiting");
    exit(report_summary());
}

static bool sel_cr0_bug_check(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_CR0_SEL_WRITE;
}

static void npt_nx_prepare(struct test *test)
{

    u64 *pte;

    vmcb_ident(test->vmcb);
    pte = npt_get_pte((u64)null_test);

    *pte |= (1ULL << 63);
}

static bool npt_nx_check(struct test *test)
{
    u64 *pte = npt_get_pte((u64)null_test);

    *pte &= ~(1ULL << 63);

    test->vmcb->save.efer |= (1 << 11);

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
           && (test->vmcb->control.exit_info_1 == 0x100000015ULL);
}

static void npt_us_prepare(struct test *test)
{
    u64 *pte;

    vmcb_ident(test->vmcb);
    pte = npt_get_pte((u64)scratch_page);

    *pte &= ~(1ULL << 2);
}

static void npt_us_test(struct test *test)
{
    (void) *(volatile u64 *)scratch_page;
}

static bool npt_us_check(struct test *test)
{
    u64 *pte = npt_get_pte((u64)scratch_page);

    *pte |= (1ULL << 2);

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
           && (test->vmcb->control.exit_info_1 == 0x100000005ULL);
}

u64 save_pde;

static void npt_rsvd_prepare(struct test *test)
{
    u64 *pde;

    vmcb_ident(test->vmcb);
    pde = npt_get_pde((u64) null_test);

    save_pde = *pde;
    *pde = (1ULL << 19) | (1ULL << 7) | 0x27;
}

static bool npt_rsvd_check(struct test *test)
{
    u64 *pde = npt_get_pde((u64) null_test);

    *pde = save_pde;

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
            && (test->vmcb->control.exit_info_1 == 0x10000001dULL);
}

static void npt_rw_prepare(struct test *test)
{

    u64 *pte;

    vmcb_ident(test->vmcb);
    pte = npt_get_pte(0x80000);

    *pte &= ~(1ULL << 1);
}

static void npt_rw_test(struct test *test)
{
    u64 *data = (void*)(0x80000);

    *data = 0;
}

static bool npt_rw_check(struct test *test)
{
    u64 *pte = npt_get_pte(0x80000);

    *pte |= (1ULL << 1);

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
           && (test->vmcb->control.exit_info_1 == 0x100000007ULL);
}

static void npt_rw_pfwalk_prepare(struct test *test)
{

    u64 *pte;

    vmcb_ident(test->vmcb);
    pte = npt_get_pte(read_cr3());

    *pte &= ~(1ULL << 1);
}

static bool npt_rw_pfwalk_check(struct test *test)
{
    u64 *pte = npt_get_pte(read_cr3());

    *pte |= (1ULL << 1);

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
           && (test->vmcb->control.exit_info_1 == 0x200000006ULL)
	   && (test->vmcb->control.exit_info_2 == read_cr3());
}

static void npt_rsvd_pfwalk_prepare(struct test *test)
{

    vmcb_ident(test->vmcb);

    pdpe[0] |= (1ULL << 8);
}

static bool npt_rsvd_pfwalk_check(struct test *test)
{
    pdpe[0] &= ~(1ULL << 8);

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
            && (test->vmcb->control.exit_info_1 == 0x20000000eULL);
}

static void npt_l1mmio_prepare(struct test *test)
{
    vmcb_ident(test->vmcb);
}

u32 nested_apic_version1;
u32 nested_apic_version2;

static void npt_l1mmio_test(struct test *test)
{
    volatile u32 *data = (volatile void*)(0xfee00030UL);

    nested_apic_version1 = *data;
    nested_apic_version2 = *data;
}

static bool npt_l1mmio_check(struct test *test)
{
    volatile u32 *data = (volatile void*)(0xfee00030);
    u32 lvr = *data;

    return nested_apic_version1 == lvr && nested_apic_version2 == lvr;
}

static void npt_rw_l1mmio_prepare(struct test *test)
{

    u64 *pte;

    vmcb_ident(test->vmcb);
    pte = npt_get_pte(0xfee00080);

    *pte &= ~(1ULL << 1);
}

static void npt_rw_l1mmio_test(struct test *test)
{
    volatile u32 *data = (volatile void*)(0xfee00080);

    *data = *data;
}

static bool npt_rw_l1mmio_check(struct test *test)
{
    u64 *pte = npt_get_pte(0xfee00080);

    *pte |= (1ULL << 1);

    return (test->vmcb->control.exit_code == SVM_EXIT_NPF)
           && (test->vmcb->control.exit_info_1 == 0x100000007ULL);
}

#define TSC_ADJUST_VALUE    (1ll << 32)
#define TSC_OFFSET_VALUE    (-1ll << 48)
static bool ok;

static void tsc_adjust_prepare(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.tsc_offset = TSC_OFFSET_VALUE;

    wrmsr(MSR_IA32_TSC_ADJUST, -TSC_ADJUST_VALUE);
    int64_t adjust = rdmsr(MSR_IA32_TSC_ADJUST);
    ok = adjust == -TSC_ADJUST_VALUE;
}

static void tsc_adjust_test(struct test *test)
{
    int64_t adjust = rdmsr(MSR_IA32_TSC_ADJUST);
    ok &= adjust == -TSC_ADJUST_VALUE;

    uint64_t l1_tsc = rdtsc() - TSC_OFFSET_VALUE;
    wrmsr(MSR_IA32_TSC, l1_tsc - TSC_ADJUST_VALUE);

    adjust = rdmsr(MSR_IA32_TSC_ADJUST);
    ok &= adjust <= -2 * TSC_ADJUST_VALUE;

    uint64_t l1_tsc_end = rdtsc() - TSC_OFFSET_VALUE;
    ok &= (l1_tsc_end + TSC_ADJUST_VALUE - l1_tsc) < TSC_ADJUST_VALUE;

    uint64_t l1_tsc_msr = rdmsr(MSR_IA32_TSC) - TSC_OFFSET_VALUE;
    ok &= (l1_tsc_msr + TSC_ADJUST_VALUE - l1_tsc) < TSC_ADJUST_VALUE;
}

static bool tsc_adjust_check(struct test *test)
{
    int64_t adjust = rdmsr(MSR_IA32_TSC_ADJUST);

    wrmsr(MSR_IA32_TSC_ADJUST, 0);
    return ok && adjust <= -2 * TSC_ADJUST_VALUE;
}

static void latency_prepare(struct test *test)
{
    default_prepare(test);
    runs = LATENCY_RUNS;
    latvmrun_min = latvmexit_min = -1ULL;
    latvmrun_max = latvmexit_max = 0;
    vmrun_sum = vmexit_sum = 0;
}

static void latency_test(struct test *test)
{
    u64 cycles;

start:
    tsc_end = rdtsc();

    cycles = tsc_end - tsc_start;

    if (cycles > latvmrun_max)
        latvmrun_max = cycles;

    if (cycles < latvmrun_min)
        latvmrun_min = cycles;

    vmrun_sum += cycles;

    tsc_start = rdtsc();

    asm volatile ("vmmcall" : : : "memory");
    goto start;
}

static bool latency_finished(struct test *test)
{
    u64 cycles;

    tsc_end = rdtsc();

    cycles = tsc_end - tsc_start;

    if (cycles > latvmexit_max)
        latvmexit_max = cycles;

    if (cycles < latvmexit_min)
        latvmexit_min = cycles;

    vmexit_sum += cycles;

    test->vmcb->save.rip += 3;

    runs -= 1;

    return runs == 0;
}

static bool latency_check(struct test *test)
{
    printf("    Latency VMRUN : max: %ld min: %ld avg: %ld\n", latvmrun_max,
            latvmrun_min, vmrun_sum / LATENCY_RUNS);
    printf("    Latency VMEXIT: max: %ld min: %ld avg: %ld\n", latvmexit_max,
            latvmexit_min, vmexit_sum / LATENCY_RUNS);
    return true;
}

static void lat_svm_insn_prepare(struct test *test)
{
    default_prepare(test);
    runs = LATENCY_RUNS;
    latvmload_min = latvmsave_min = latstgi_min = latclgi_min = -1ULL;
    latvmload_max = latvmsave_max = latstgi_max = latclgi_max = 0;
    vmload_sum = vmsave_sum = stgi_sum = clgi_sum;
}

static bool lat_svm_insn_finished(struct test *test)
{
    u64 vmcb_phys = virt_to_phys(test->vmcb);
    u64 cycles;

    for ( ; runs != 0; runs--) {
        tsc_start = rdtsc();
        asm volatile("vmload %0\n\t" : : "a"(vmcb_phys) : "memory");
        cycles = rdtsc() - tsc_start;
        if (cycles > latvmload_max)
            latvmload_max = cycles;
        if (cycles < latvmload_min)
            latvmload_min = cycles;
        vmload_sum += cycles;

        tsc_start = rdtsc();
        asm volatile("vmsave %0\n\t" : : "a"(vmcb_phys) : "memory");
        cycles = rdtsc() - tsc_start;
        if (cycles > latvmsave_max)
            latvmsave_max = cycles;
        if (cycles < latvmsave_min)
            latvmsave_min = cycles;
        vmsave_sum += cycles;

        tsc_start = rdtsc();
        asm volatile("stgi\n\t");
        cycles = rdtsc() - tsc_start;
        if (cycles > latstgi_max)
            latstgi_max = cycles;
        if (cycles < latstgi_min)
            latstgi_min = cycles;
        stgi_sum += cycles;

        tsc_start = rdtsc();
        asm volatile("clgi\n\t");
        cycles = rdtsc() - tsc_start;
        if (cycles > latclgi_max)
            latclgi_max = cycles;
        if (cycles < latclgi_min)
            latclgi_min = cycles;
        clgi_sum += cycles;
    }

    return true;
}

static bool lat_svm_insn_check(struct test *test)
{
    printf("    Latency VMLOAD: max: %ld min: %ld avg: %ld\n", latvmload_max,
            latvmload_min, vmload_sum / LATENCY_RUNS);
    printf("    Latency VMSAVE: max: %ld min: %ld avg: %ld\n", latvmsave_max,
            latvmsave_min, vmsave_sum / LATENCY_RUNS);
    printf("    Latency STGI:   max: %ld min: %ld avg: %ld\n", latstgi_max,
            latstgi_min, stgi_sum / LATENCY_RUNS);
    printf("    Latency CLGI:   max: %ld min: %ld avg: %ld\n", latclgi_max,
            latclgi_min, clgi_sum / LATENCY_RUNS);
    return true;
}

bool pending_event_ipi_fired;
bool pending_event_guest_run;

static void pending_event_ipi_isr(isr_regs_t *regs)
{
    pending_event_ipi_fired = true;
    eoi();
}

static void pending_event_prepare(struct test *test)
{
    int ipi_vector = 0xf1;

    default_prepare(test);

    pending_event_ipi_fired = false;

    handle_irq(ipi_vector, pending_event_ipi_isr);

    pending_event_guest_run = false;

    test->vmcb->control.intercept |= (1ULL << INTERCEPT_INTR);
    test->vmcb->control.int_ctl |= V_INTR_MASKING_MASK;

    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
                  APIC_DM_FIXED | ipi_vector, 0);

    set_test_stage(test, 0);
}

static void pending_event_test(struct test *test)
{
    pending_event_guest_run = true;
}

static bool pending_event_finished(struct test *test)
{
    switch (get_test_stage(test)) {
    case 0:
        if (test->vmcb->control.exit_code != SVM_EXIT_INTR) {
            report(false, "VMEXIT not due to pending interrupt. Exit reason 0x%x",
                   test->vmcb->control.exit_code);
            return true;
        }

        test->vmcb->control.intercept &= ~(1ULL << INTERCEPT_INTR);
        test->vmcb->control.int_ctl &= ~V_INTR_MASKING_MASK;

        if (pending_event_guest_run) {
            report(false, "Guest ran before host received IPI\n");
            return true;
        }

        irq_enable();
        asm volatile ("nop");
        irq_disable();

        if (!pending_event_ipi_fired) {
            report(false, "Pending interrupt not dispatched after IRQ enabled\n");
            return true;
        }
        break;

    case 1:
        if (!pending_event_guest_run) {
            report(false, "Guest did not resume when no interrupt\n");
            return true;
        }
        break;
    }

    inc_test_stage(test);

    return get_test_stage(test) == 2;
}

static bool pending_event_check(struct test *test)
{
    return get_test_stage(test) == 2;
}

static void pending_event_prepare_vmask(struct test *test)
{
    default_prepare(test);

    pending_event_ipi_fired = false;

    handle_irq(0xf1, pending_event_ipi_isr);

    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
              APIC_DM_FIXED | 0xf1, 0);

    set_test_stage(test, 0);
}

static void pending_event_prepare_gif_clear_vmask(struct test *test)
{
    asm("cli");
}

static void pending_event_test_vmask(struct test *test)
{
    if (pending_event_ipi_fired == true) {
        set_test_stage(test, -1);
        report(false, "Interrupt preceeded guest");
        vmmcall();
    }

    irq_enable();
    asm volatile ("nop");
    irq_disable();

    if (pending_event_ipi_fired != true) {
        set_test_stage(test, -1);
        report(false, "Interrupt not triggered by guest");
    }

    vmmcall();

    irq_enable();
    asm volatile ("nop");
    irq_disable();
}

static bool pending_event_finished_vmask(struct test *test)
{
    if ( test->vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
        report(false, "VM_EXIT return to host is not EXIT_VMMCALL exit reason 0x%x",
               test->vmcb->control.exit_code);
        return true;
    }

    switch (get_test_stage(test)) {
    case 0:
        test->vmcb->save.rip += 3;

        pending_event_ipi_fired = false;

        test->vmcb->control.int_ctl |= V_INTR_MASKING_MASK;

        apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
              APIC_DM_FIXED | 0xf1, 0);

        break;

    case 1:
        if (pending_event_ipi_fired == true) {
            report(false, "Interrupt triggered by guest");
            return true;
        }

        irq_enable();
        asm volatile ("nop");
        irq_disable();

        if (pending_event_ipi_fired != true) {
            report(false, "Interrupt not triggered by host");
            return true;
        }

        break;

    default:
        return true;
    }

    inc_test_stage(test);

    return get_test_stage(test) == 2;
}

static bool pending_event_check_vmask(struct test *test)
{
    return get_test_stage(test) == 2;
}

static struct test tests[] = {
    { "null", default_supported, default_prepare,
      default_prepare_gif_clear, null_test,
      default_finished, null_check },
    { "vmrun", default_supported, default_prepare,
      default_prepare_gif_clear, test_vmrun,
       default_finished, check_vmrun },
    { "ioio", default_supported, prepare_ioio,
       default_prepare_gif_clear, test_ioio,
       ioio_finished, check_ioio },
    { "vmrun intercept check", default_supported, prepare_no_vmrun_int,
      default_prepare_gif_clear, null_test, default_finished,
      check_no_vmrun_int },
    { "cr3 read intercept", default_supported,
      prepare_cr3_intercept, default_prepare_gif_clear,
      test_cr3_intercept, default_finished, check_cr3_intercept },
    { "cr3 read nointercept", default_supported, default_prepare,
      default_prepare_gif_clear, test_cr3_intercept, default_finished,
      check_cr3_nointercept },
    { "cr3 read intercept emulate", smp_supported,
      prepare_cr3_intercept_bypass, default_prepare_gif_clear,
      test_cr3_intercept_bypass, default_finished, check_cr3_intercept },
    { "dr intercept check", default_supported, prepare_dr_intercept,
      default_prepare_gif_clear, test_dr_intercept, dr_intercept_finished,
      check_dr_intercept },
    { "next_rip", next_rip_supported, prepare_next_rip,
      default_prepare_gif_clear, test_next_rip,
      default_finished, check_next_rip },
    { "msr intercept check", default_supported, prepare_msr_intercept,
      default_prepare_gif_clear, test_msr_intercept,
      msr_intercept_finished, check_msr_intercept },
    { "mode_switch", default_supported, prepare_mode_switch,
      default_prepare_gif_clear, test_mode_switch,
       mode_switch_finished, check_mode_switch },
    { "asid_zero", default_supported, prepare_asid_zero,
      default_prepare_gif_clear, test_asid_zero,
       default_finished, check_asid_zero },
    { "sel_cr0_bug", default_supported, sel_cr0_bug_prepare,
      default_prepare_gif_clear, sel_cr0_bug_test,
       sel_cr0_bug_finished, sel_cr0_bug_check },
    { "npt_nx", npt_supported, npt_nx_prepare,
      default_prepare_gif_clear, null_test,
      default_finished, npt_nx_check },
    { "npt_us", npt_supported, npt_us_prepare,
      default_prepare_gif_clear, npt_us_test,
      default_finished, npt_us_check },
    { "npt_rsvd", npt_supported, npt_rsvd_prepare,
      default_prepare_gif_clear, null_test,
      default_finished, npt_rsvd_check },
    { "npt_rw", npt_supported, npt_rw_prepare,
      default_prepare_gif_clear, npt_rw_test,
      default_finished, npt_rw_check },
    { "npt_rsvd_pfwalk", npt_supported, npt_rsvd_pfwalk_prepare,
      default_prepare_gif_clear, null_test,
      default_finished, npt_rsvd_pfwalk_check },
    { "npt_rw_pfwalk", npt_supported, npt_rw_pfwalk_prepare,
      default_prepare_gif_clear, null_test,
      default_finished, npt_rw_pfwalk_check },
    { "npt_l1mmio", npt_supported, npt_l1mmio_prepare,
      default_prepare_gif_clear, npt_l1mmio_test,
      default_finished, npt_l1mmio_check },
    { "npt_rw_l1mmio", npt_supported, npt_rw_l1mmio_prepare,
      default_prepare_gif_clear, npt_rw_l1mmio_test,
      default_finished, npt_rw_l1mmio_check },
    { "tsc_adjust", default_supported, tsc_adjust_prepare,
      default_prepare_gif_clear, tsc_adjust_test,
      default_finished, tsc_adjust_check },
    { "latency_run_exit", default_supported, latency_prepare,
      default_prepare_gif_clear, latency_test,
      latency_finished, latency_check },
    { "latency_svm_insn", default_supported, lat_svm_insn_prepare,
      default_prepare_gif_clear, null_test,
      lat_svm_insn_finished, lat_svm_insn_check },
    { "pending_event", default_supported, pending_event_prepare,
      default_prepare_gif_clear,
      pending_event_test, pending_event_finished, pending_event_check },
    { "pending_event_vmask", default_supported, pending_event_prepare_vmask,
      pending_event_prepare_gif_clear_vmask,
      pending_event_test_vmask, pending_event_finished_vmask,
      pending_event_check_vmask },
};

int matched;

static bool
test_wanted(const char *name, char *filters[], int filter_count)
{
        int i;
        bool positive = false;
        bool match = false;
        char clean_name[strlen(name) + 1];
        char *c;
        const char *n;

        /* Replace spaces with underscores. */
        n = name;
        c = &clean_name[0];
        do *c++ = (*n == ' ') ? '_' : *n;
        while (*n++);

        for (i = 0; i < filter_count; i++) {
                const char *filter = filters[i];

                if (filter[0] == '-') {
                        if (simple_glob(clean_name, filter + 1))
                                return false;
                } else {
                        positive = true;
                        match |= simple_glob(clean_name, filter);
                }
        }

        if (!positive || match) {
                matched++;
                return true;
        } else {
                return false;
        }
}

int main(int ac, char **av)
{
    int i, nr;
    struct vmcb *vmcb;

    ac--;
    av++;

    setup_vm();
    smp_init();

    if (!this_cpu_has(X86_FEATURE_SVM)) {
        printf("SVM not availble\n");
        return report_summary();
    }

    setup_svm();

    vmcb = alloc_page();

    nr = ARRAY_SIZE(tests);
    for (i = 0; i < nr; ++i) {
        if (!test_wanted(tests[i].name, av, ac) || !tests[i].supported())
            continue;
        test_run(&tests[i], vmcb);
    }

    if (!matched)
        report(matched, "command line didn't match any tests!");

    return report_summary();
}
