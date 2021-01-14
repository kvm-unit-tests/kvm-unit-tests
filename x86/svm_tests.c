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
#include "delay.h"

#define SVM_EXIT_MAX_DR_INTERCEPT 0x3f

static void *scratch_page;

#define LATENCY_RUNS 1000000

extern u16 cpu_online_count;

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

static void null_test(struct svm_test *test)
{
}

static bool null_check(struct svm_test *test)
{
    return vmcb->control.exit_code == SVM_EXIT_VMMCALL;
}

static void prepare_no_vmrun_int(struct svm_test *test)
{
    vmcb->control.intercept &= ~(1ULL << INTERCEPT_VMRUN);
}

static bool check_no_vmrun_int(struct svm_test *test)
{
    return vmcb->control.exit_code == SVM_EXIT_ERR;
}

static void test_vmrun(struct svm_test *test)
{
    asm volatile ("vmrun %0" : : "a"(virt_to_phys(vmcb)));
}

static bool check_vmrun(struct svm_test *test)
{
    return vmcb->control.exit_code == SVM_EXIT_VMRUN;
}

static void prepare_rsm_intercept(struct svm_test *test)
{
    default_prepare(test);
    vmcb->control.intercept |= 1 << INTERCEPT_RSM;
    vmcb->control.intercept_exceptions |= (1ULL << UD_VECTOR);
}

static void test_rsm_intercept(struct svm_test *test)
{
    asm volatile ("rsm" : : : "memory");
}

static bool check_rsm_intercept(struct svm_test *test)
{
    return get_test_stage(test) == 2;
}

static bool finished_rsm_intercept(struct svm_test *test)
{
    switch (get_test_stage(test)) {
    case 0:
        if (vmcb->control.exit_code != SVM_EXIT_RSM) {
            report(false, "VMEXIT not due to rsm. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->control.intercept &= ~(1 << INTERCEPT_RSM);
        inc_test_stage(test);
        break;

    case 1:
        if (vmcb->control.exit_code != SVM_EXIT_EXCP_BASE + UD_VECTOR) {
            report(false, "VMEXIT not due to #UD. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->save.rip += 2;
        inc_test_stage(test);
        break;

    default:
        return true;
    }
    return get_test_stage(test) == 2;
}

static void prepare_cr3_intercept(struct svm_test *test)
{
    default_prepare(test);
    vmcb->control.intercept_cr_read |= 1 << 3;
}

static void test_cr3_intercept(struct svm_test *test)
{
    asm volatile ("mov %%cr3, %0" : "=r"(test->scratch) : : "memory");
}

static bool check_cr3_intercept(struct svm_test *test)
{
    return vmcb->control.exit_code == SVM_EXIT_READ_CR3;
}

static bool check_cr3_nointercept(struct svm_test *test)
{
    return null_check(test) && test->scratch == read_cr3();
}

static void corrupt_cr3_intercept_bypass(void *_test)
{
    struct svm_test *test = _test;
    extern volatile u32 mmio_insn;

    while (!__sync_bool_compare_and_swap(&test->scratch, 1, 2))
        pause();
    pause();
    pause();
    pause();
    mmio_insn = 0x90d8200f;  // mov %cr3, %rax; nop
}

static void prepare_cr3_intercept_bypass(struct svm_test *test)
{
    default_prepare(test);
    vmcb->control.intercept_cr_read |= 1 << 3;
    on_cpu_async(1, corrupt_cr3_intercept_bypass, test);
}

static void test_cr3_intercept_bypass(struct svm_test *test)
{
    ulong a = 0xa0000;

    test->scratch = 1;
    while (test->scratch != 2)
        barrier();

    asm volatile ("mmio_insn: mov %0, (%0); nop"
                  : "+a"(a) : : "memory");
    test->scratch = a;
}

static void prepare_dr_intercept(struct svm_test *test)
{
    default_prepare(test);
    vmcb->control.intercept_dr_read = 0xff;
    vmcb->control.intercept_dr_write = 0xff;
}

static void test_dr_intercept(struct svm_test *test)
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

static bool dr_intercept_finished(struct svm_test *test)
{
    ulong n = (vmcb->control.exit_code - SVM_EXIT_READ_DR0);

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
    vmcb->save.rip += 3;

    return false;
}

static bool check_dr_intercept(struct svm_test *test)
{
    return !test->scratch;
}

static bool next_rip_supported(void)
{
    return this_cpu_has(X86_FEATURE_NRIPS);
}

static void prepare_next_rip(struct svm_test *test)
{
    vmcb->control.intercept |= (1ULL << INTERCEPT_RDTSC);
}


static void test_next_rip(struct svm_test *test)
{
    asm volatile ("rdtsc\n\t"
                  ".globl exp_next_rip\n\t"
                  "exp_next_rip:\n\t" ::: "eax", "edx");
}

static bool check_next_rip(struct svm_test *test)
{
    extern char exp_next_rip;
    unsigned long address = (unsigned long)&exp_next_rip;

    return address == vmcb->control.next_rip;
}

extern u8 *msr_bitmap;

static void prepare_msr_intercept(struct svm_test *test)
{
    default_prepare(test);
    vmcb->control.intercept |= (1ULL << INTERCEPT_MSR_PROT);
    vmcb->control.intercept_exceptions |= (1ULL << GP_VECTOR);
    memset(msr_bitmap, 0xff, MSR_BITMAP_SIZE);
}

static void test_msr_intercept(struct svm_test *test)
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

static bool msr_intercept_finished(struct svm_test *test)
{
    u32 exit_code = vmcb->control.exit_code;
    u64 exit_info_1;
    u8 *opcode;

    if (exit_code == SVM_EXIT_MSR) {
        exit_info_1 = vmcb->control.exit_info_1;
    } else {
        /*
         * If #GP exception occurs instead, check that it was
         * for RDMSR/WRMSR and set exit_info_1 accordingly.
         */

        if (exit_code != (SVM_EXIT_EXCP_BASE + GP_VECTOR))
            return true;

        opcode = (u8 *)vmcb->save.rip;
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
            exit_info_1 ? "WRMSR" : "RDMSR", get_regs().rcx);
    }

    /* Jump over RDMSR/WRMSR instruction */
    vmcb->save.rip += 2;

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
            ((get_regs().rdx << 32) | (vmcb->save.rax & 0xffffffff));
    else
        test->scratch = get_regs().rcx;

    return false;
}

static bool check_msr_intercept(struct svm_test *test)
{
    memset(msr_bitmap, 0, MSR_BITMAP_SIZE);
    return (test->scratch == -2);
}

static void prepare_mode_switch(struct svm_test *test)
{
    vmcb->control.intercept_exceptions |= (1ULL << GP_VECTOR)
                                             |  (1ULL << UD_VECTOR)
                                             |  (1ULL << DF_VECTOR)
                                             |  (1ULL << PF_VECTOR);
    test->scratch = 0;
}

static void test_mode_switch(struct svm_test *test)
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

static bool mode_switch_finished(struct svm_test *test)
{
    u64 cr0, cr4, efer;

    cr0  = vmcb->save.cr0;
    cr4  = vmcb->save.cr4;
    efer = vmcb->save.efer;

    /* Only expect VMMCALL intercepts */
    if (vmcb->control.exit_code != SVM_EXIT_VMMCALL)
	    return true;

    /* Jump over VMMCALL instruction */
    vmcb->save.rip += 3;

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

static bool check_mode_switch(struct svm_test *test)
{
	return test->scratch == 2;
}

extern u8 *io_bitmap;

static void prepare_ioio(struct svm_test *test)
{
    vmcb->control.intercept |= (1ULL << INTERCEPT_IOIO_PROT);
    test->scratch = 0;
    memset(io_bitmap, 0, 8192);
    io_bitmap[8192] = 0xFF;
}

static void test_ioio(struct svm_test *test)
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

static bool ioio_finished(struct svm_test *test)
{
    unsigned port, size;

    /* Only expect IOIO intercepts */
    if (vmcb->control.exit_code == SVM_EXIT_VMMCALL)
        return true;

    if (vmcb->control.exit_code != SVM_EXIT_IOIO)
        return true;

    /* one step forward */
    test->scratch += 1;

    port = vmcb->control.exit_info_1 >> 16;
    size = (vmcb->control.exit_info_1 >> SVM_IOIO_SIZE_SHIFT) & 7;

    while (size--) {
        io_bitmap[port / 8] &= ~(1 << (port & 7));
        port++;
    }

    return false;
}

static bool check_ioio(struct svm_test *test)
{
    memset(io_bitmap, 0, 8193);
    return test->scratch != -1;
}

static void prepare_asid_zero(struct svm_test *test)
{
    vmcb->control.asid = 0;
}

static void test_asid_zero(struct svm_test *test)
{
    asm volatile ("vmmcall\n\t");
}

static bool check_asid_zero(struct svm_test *test)
{
    return vmcb->control.exit_code == SVM_EXIT_ERR;
}

static void sel_cr0_bug_prepare(struct svm_test *test)
{
    vmcb_ident(vmcb);
    vmcb->control.intercept |= (1ULL << INTERCEPT_SELECTIVE_CR0);
}

static bool sel_cr0_bug_finished(struct svm_test *test)
{
	return true;
}

static void sel_cr0_bug_test(struct svm_test *test)
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

static bool sel_cr0_bug_check(struct svm_test *test)
{
    return vmcb->control.exit_code == SVM_EXIT_CR0_SEL_WRITE;
}

static void npt_nx_prepare(struct svm_test *test)
{

    u64 *pte;

    vmcb_ident(vmcb);
    pte = npt_get_pte((u64)null_test);

    *pte |= (1ULL << 63);
}

static bool npt_nx_check(struct svm_test *test)
{
    u64 *pte = npt_get_pte((u64)null_test);

    *pte &= ~(1ULL << 63);

    vmcb->save.efer |= (1 << 11);

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
           && (vmcb->control.exit_info_1 == 0x100000015ULL);
}

static void npt_np_prepare(struct svm_test *test)
{
    u64 *pte;

    scratch_page = alloc_page();
    vmcb_ident(vmcb);
    pte = npt_get_pte((u64)scratch_page);

    *pte &= ~1ULL;
}

static void npt_np_test(struct svm_test *test)
{
    (void) *(volatile u64 *)scratch_page;
}

static bool npt_np_check(struct svm_test *test)
{
    u64 *pte = npt_get_pte((u64)scratch_page);

    *pte |= 1ULL;

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
           && (vmcb->control.exit_info_1 == 0x100000004ULL);
}

static void npt_us_prepare(struct svm_test *test)
{
    u64 *pte;

    scratch_page = alloc_page();
    vmcb_ident(vmcb);
    pte = npt_get_pte((u64)scratch_page);

    *pte &= ~(1ULL << 2);
}

static void npt_us_test(struct svm_test *test)
{
    (void) *(volatile u64 *)scratch_page;
}

static bool npt_us_check(struct svm_test *test)
{
    u64 *pte = npt_get_pte((u64)scratch_page);

    *pte |= (1ULL << 2);

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
           && (vmcb->control.exit_info_1 == 0x100000005ULL);
}

u64 save_pde;

static void npt_rsvd_prepare(struct svm_test *test)
{
    u64 *pde;

    vmcb_ident(vmcb);
    pde = npt_get_pde((u64) null_test);

    save_pde = *pde;
    *pde = (1ULL << 19) | (1ULL << 7) | 0x27;
}

static bool npt_rsvd_check(struct svm_test *test)
{
    u64 *pde = npt_get_pde((u64) null_test);

    *pde = save_pde;

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
            && (vmcb->control.exit_info_1 == 0x10000001dULL);
}

static void npt_rw_prepare(struct svm_test *test)
{

    u64 *pte;

    vmcb_ident(vmcb);
    pte = npt_get_pte(0x80000);

    *pte &= ~(1ULL << 1);
}

static void npt_rw_test(struct svm_test *test)
{
    u64 *data = (void*)(0x80000);

    *data = 0;
}

static bool npt_rw_check(struct svm_test *test)
{
    u64 *pte = npt_get_pte(0x80000);

    *pte |= (1ULL << 1);

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
           && (vmcb->control.exit_info_1 == 0x100000007ULL);
}

static void npt_rw_pfwalk_prepare(struct svm_test *test)
{

    u64 *pte;

    vmcb_ident(vmcb);
    pte = npt_get_pte(read_cr3());

    *pte &= ~(1ULL << 1);
}

static bool npt_rw_pfwalk_check(struct svm_test *test)
{
    u64 *pte = npt_get_pte(read_cr3());

    *pte |= (1ULL << 1);

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
           && (vmcb->control.exit_info_1 == 0x200000007ULL)
	   && (vmcb->control.exit_info_2 == read_cr3());
}

static void npt_rsvd_pfwalk_prepare(struct svm_test *test)
{
    u64 *pdpe;
    vmcb_ident(vmcb);

    pdpe = npt_get_pml4e();
    pdpe[0] |= (1ULL << 8);
}

static bool npt_rsvd_pfwalk_check(struct svm_test *test)
{
    u64 *pdpe = npt_get_pml4e();
    pdpe[0] &= ~(1ULL << 8);

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
            && (vmcb->control.exit_info_1 == 0x20000000fULL);
}

static void npt_l1mmio_prepare(struct svm_test *test)
{
    vmcb_ident(vmcb);
}

u32 nested_apic_version1;
u32 nested_apic_version2;

static void npt_l1mmio_test(struct svm_test *test)
{
    volatile u32 *data = (volatile void*)(0xfee00030UL);

    nested_apic_version1 = *data;
    nested_apic_version2 = *data;
}

static bool npt_l1mmio_check(struct svm_test *test)
{
    volatile u32 *data = (volatile void*)(0xfee00030);
    u32 lvr = *data;

    return nested_apic_version1 == lvr && nested_apic_version2 == lvr;
}

static void npt_rw_l1mmio_prepare(struct svm_test *test)
{

    u64 *pte;

    vmcb_ident(vmcb);
    pte = npt_get_pte(0xfee00080);

    *pte &= ~(1ULL << 1);
}

static void npt_rw_l1mmio_test(struct svm_test *test)
{
    volatile u32 *data = (volatile void*)(0xfee00080);

    *data = *data;
}

static bool npt_rw_l1mmio_check(struct svm_test *test)
{
    u64 *pte = npt_get_pte(0xfee00080);

    *pte |= (1ULL << 1);

    return (vmcb->control.exit_code == SVM_EXIT_NPF)
           && (vmcb->control.exit_info_1 == 0x100000007ULL);
}

#define TSC_ADJUST_VALUE    (1ll << 32)
#define TSC_OFFSET_VALUE    (~0ull << 48)
static bool ok;

static bool tsc_adjust_supported(void)
{
    return this_cpu_has(X86_FEATURE_TSC_ADJUST);
}

static void tsc_adjust_prepare(struct svm_test *test)
{
    default_prepare(test);
    vmcb->control.tsc_offset = TSC_OFFSET_VALUE;

    wrmsr(MSR_IA32_TSC_ADJUST, -TSC_ADJUST_VALUE);
    int64_t adjust = rdmsr(MSR_IA32_TSC_ADJUST);
    ok = adjust == -TSC_ADJUST_VALUE;
}

static void tsc_adjust_test(struct svm_test *test)
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

static bool tsc_adjust_check(struct svm_test *test)
{
    int64_t adjust = rdmsr(MSR_IA32_TSC_ADJUST);

    wrmsr(MSR_IA32_TSC_ADJUST, 0);
    return ok && adjust <= -2 * TSC_ADJUST_VALUE;
}

static void latency_prepare(struct svm_test *test)
{
    default_prepare(test);
    runs = LATENCY_RUNS;
    latvmrun_min = latvmexit_min = -1ULL;
    latvmrun_max = latvmexit_max = 0;
    vmrun_sum = vmexit_sum = 0;
    tsc_start = rdtsc();
}

static void latency_test(struct svm_test *test)
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

static bool latency_finished(struct svm_test *test)
{
    u64 cycles;

    tsc_end = rdtsc();

    cycles = tsc_end - tsc_start;

    if (cycles > latvmexit_max)
        latvmexit_max = cycles;

    if (cycles < latvmexit_min)
        latvmexit_min = cycles;

    vmexit_sum += cycles;

    vmcb->save.rip += 3;

    runs -= 1;

    tsc_end = rdtsc();

    return runs == 0;
}

static bool latency_check(struct svm_test *test)
{
    printf("    Latency VMRUN : max: %ld min: %ld avg: %ld\n", latvmrun_max,
            latvmrun_min, vmrun_sum / LATENCY_RUNS);
    printf("    Latency VMEXIT: max: %ld min: %ld avg: %ld\n", latvmexit_max,
            latvmexit_min, vmexit_sum / LATENCY_RUNS);
    return true;
}

static void lat_svm_insn_prepare(struct svm_test *test)
{
    default_prepare(test);
    runs = LATENCY_RUNS;
    latvmload_min = latvmsave_min = latstgi_min = latclgi_min = -1ULL;
    latvmload_max = latvmsave_max = latstgi_max = latclgi_max = 0;
    vmload_sum = vmsave_sum = stgi_sum = clgi_sum;
}

static bool lat_svm_insn_finished(struct svm_test *test)
{
    u64 vmcb_phys = virt_to_phys(vmcb);
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

    tsc_end = rdtsc();

    return true;
}

static bool lat_svm_insn_check(struct svm_test *test)
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

static void pending_event_prepare(struct svm_test *test)
{
    int ipi_vector = 0xf1;

    default_prepare(test);

    pending_event_ipi_fired = false;

    handle_irq(ipi_vector, pending_event_ipi_isr);

    pending_event_guest_run = false;

    vmcb->control.intercept |= (1ULL << INTERCEPT_INTR);
    vmcb->control.int_ctl |= V_INTR_MASKING_MASK;

    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
                  APIC_DM_FIXED | ipi_vector, 0);

    set_test_stage(test, 0);
}

static void pending_event_test(struct svm_test *test)
{
    pending_event_guest_run = true;
}

static bool pending_event_finished(struct svm_test *test)
{
    switch (get_test_stage(test)) {
    case 0:
        if (vmcb->control.exit_code != SVM_EXIT_INTR) {
            report(false, "VMEXIT not due to pending interrupt. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }

        vmcb->control.intercept &= ~(1ULL << INTERCEPT_INTR);
        vmcb->control.int_ctl &= ~V_INTR_MASKING_MASK;

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

static bool pending_event_check(struct svm_test *test)
{
    return get_test_stage(test) == 2;
}

static void pending_event_cli_prepare(struct svm_test *test)
{
    default_prepare(test);

    pending_event_ipi_fired = false;

    handle_irq(0xf1, pending_event_ipi_isr);

    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
              APIC_DM_FIXED | 0xf1, 0);

    set_test_stage(test, 0);
}

static void pending_event_cli_prepare_gif_clear(struct svm_test *test)
{
    asm("cli");
}

static void pending_event_cli_test(struct svm_test *test)
{
    if (pending_event_ipi_fired == true) {
        set_test_stage(test, -1);
        report(false, "Interrupt preceeded guest");
        vmmcall();
    }

    /* VINTR_MASKING is zero.  This should cause the IPI to fire.  */
    irq_enable();
    asm volatile ("nop");
    irq_disable();

    if (pending_event_ipi_fired != true) {
        set_test_stage(test, -1);
        report(false, "Interrupt not triggered by guest");
    }

    vmmcall();

    /*
     * Now VINTR_MASKING=1, but no interrupt is pending so
     * the VINTR interception should be clear in VMCB02.  Check
     * that L0 did not leave a stale VINTR in the VMCB.
     */
    irq_enable();
    asm volatile ("nop");
    irq_disable();
}

static bool pending_event_cli_finished(struct svm_test *test)
{
    if ( vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
        report(false, "VM_EXIT return to host is not EXIT_VMMCALL exit reason 0x%x",
               vmcb->control.exit_code);
        return true;
    }

    switch (get_test_stage(test)) {
    case 0:
        vmcb->save.rip += 3;

        pending_event_ipi_fired = false;

        vmcb->control.int_ctl |= V_INTR_MASKING_MASK;

	/* Now entering again with VINTR_MASKING=1.  */
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

static bool pending_event_cli_check(struct svm_test *test)
{
    return get_test_stage(test) == 2;
}

#define TIMER_VECTOR    222

static volatile bool timer_fired;

static void timer_isr(isr_regs_t *regs)
{
    timer_fired = true;
    apic_write(APIC_EOI, 0);
}

static void interrupt_prepare(struct svm_test *test)
{
    default_prepare(test);
    handle_irq(TIMER_VECTOR, timer_isr);
    timer_fired = false;
    set_test_stage(test, 0);
}

static void interrupt_test(struct svm_test *test)
{
    long long start, loops;

    apic_write(APIC_LVTT, TIMER_VECTOR);
    irq_enable();
    apic_write(APIC_TMICT, 1); //Timer Initial Count Register 0x380 one-shot
    for (loops = 0; loops < 10000000 && !timer_fired; loops++)
        asm volatile ("nop");

    report(timer_fired, "direct interrupt while running guest");

    if (!timer_fired) {
        set_test_stage(test, -1);
        vmmcall();
    }

    apic_write(APIC_TMICT, 0);
    irq_disable();
    vmmcall();

    timer_fired = false;
    apic_write(APIC_TMICT, 1);
    for (loops = 0; loops < 10000000 && !timer_fired; loops++)
        asm volatile ("nop");

    report(timer_fired, "intercepted interrupt while running guest");

    if (!timer_fired) {
        set_test_stage(test, -1);
        vmmcall();
    }

    irq_enable();
    apic_write(APIC_TMICT, 0);
    irq_disable();

    timer_fired = false;
    start = rdtsc();
    apic_write(APIC_TMICT, 1000000);
    asm volatile ("sti; hlt");

    report(rdtsc() - start > 10000 && timer_fired,
          "direct interrupt + hlt");

    if (!timer_fired) {
        set_test_stage(test, -1);
        vmmcall();
    }

    apic_write(APIC_TMICT, 0);
    irq_disable();
    vmmcall();

    timer_fired = false;
    start = rdtsc();
    apic_write(APIC_TMICT, 1000000);
    asm volatile ("hlt");

    report(rdtsc() - start > 10000 && timer_fired,
           "intercepted interrupt + hlt");

    if (!timer_fired) {
        set_test_stage(test, -1);
        vmmcall();
    }

    apic_write(APIC_TMICT, 0);
    irq_disable();
}

static bool interrupt_finished(struct svm_test *test)
{
    switch (get_test_stage(test)) {
    case 0:
    case 2:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->save.rip += 3;

        vmcb->control.intercept |= (1ULL << INTERCEPT_INTR);
        vmcb->control.int_ctl |= V_INTR_MASKING_MASK;
        break;

    case 1:
    case 3:
        if (vmcb->control.exit_code != SVM_EXIT_INTR) {
            report(false, "VMEXIT not due to intr intercept. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }

        irq_enable();
        asm volatile ("nop");
        irq_disable();

        vmcb->control.intercept &= ~(1ULL << INTERCEPT_INTR);
        vmcb->control.int_ctl &= ~V_INTR_MASKING_MASK;
        break;

    case 4:
        break;

    default:
        return true;
    }

    inc_test_stage(test);

    return get_test_stage(test) == 5;
}

static bool interrupt_check(struct svm_test *test)
{
    return get_test_stage(test) == 5;
}

static volatile bool nmi_fired;

static void nmi_handler(isr_regs_t *regs)
{
    nmi_fired = true;
    apic_write(APIC_EOI, 0);
}

static void nmi_prepare(struct svm_test *test)
{
    default_prepare(test);
    nmi_fired = false;
    handle_irq(NMI_VECTOR, nmi_handler);
    set_test_stage(test, 0);
}

static void nmi_test(struct svm_test *test)
{
    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, 0);

    report(nmi_fired, "direct NMI while running guest");

    if (!nmi_fired)
        set_test_stage(test, -1);

    vmmcall();

    nmi_fired = false;

    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, 0);

    if (!nmi_fired) {
        report(nmi_fired, "intercepted pending NMI not dispatched");
        set_test_stage(test, -1);
    }

}

static bool nmi_finished(struct svm_test *test)
{
    switch (get_test_stage(test)) {
    case 0:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->save.rip += 3;

        vmcb->control.intercept |= (1ULL << INTERCEPT_NMI);
        break;

    case 1:
        if (vmcb->control.exit_code != SVM_EXIT_NMI) {
            report(false, "VMEXIT not due to NMI intercept. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }

        report(true, "NMI intercept while running guest");
        break;

    case 2:
        break;

    default:
        return true;
    }

    inc_test_stage(test);

    return get_test_stage(test) == 3;
}

static bool nmi_check(struct svm_test *test)
{
    return get_test_stage(test) == 3;
}

#define NMI_DELAY 100000000ULL

static void nmi_message_thread(void *_test)
{
    struct svm_test *test = _test;

    while (get_test_stage(test) != 1)
        pause();

    delay(NMI_DELAY);

    apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, id_map[0]);

    while (get_test_stage(test) != 2)
        pause();

    delay(NMI_DELAY);

    apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, id_map[0]);
}

static void nmi_hlt_test(struct svm_test *test)
{
    long long start;

    on_cpu_async(1, nmi_message_thread, test);

    start = rdtsc();

    set_test_stage(test, 1);

    asm volatile ("hlt");

    report((rdtsc() - start > NMI_DELAY) && nmi_fired,
          "direct NMI + hlt");

    if (!nmi_fired)
        set_test_stage(test, -1);

    nmi_fired = false;

    vmmcall();

    start = rdtsc();

    set_test_stage(test, 2);

    asm volatile ("hlt");

    report((rdtsc() - start > NMI_DELAY) && nmi_fired,
           "intercepted NMI + hlt");

    if (!nmi_fired) {
        report(nmi_fired, "intercepted pending NMI not dispatched");
        set_test_stage(test, -1);
        vmmcall();
    }

    set_test_stage(test, 3);
}

static bool nmi_hlt_finished(struct svm_test *test)
{
    switch (get_test_stage(test)) {
    case 1:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->save.rip += 3;

        vmcb->control.intercept |= (1ULL << INTERCEPT_NMI);
        break;

    case 2:
        if (vmcb->control.exit_code != SVM_EXIT_NMI) {
            report(false, "VMEXIT not due to NMI intercept. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }

        report(true, "NMI intercept while running guest");
        break;

    case 3:
        break;

    default:
        return true;
    }

    return get_test_stage(test) == 3;
}

static bool nmi_hlt_check(struct svm_test *test)
{
    return get_test_stage(test) == 3;
}

static volatile int count_exc = 0;

static void my_isr(struct ex_regs *r)
{
        count_exc++;
}

static void exc_inject_prepare(struct svm_test *test)
{
    default_prepare(test);
    handle_exception(DE_VECTOR, my_isr);
    handle_exception(NMI_VECTOR, my_isr);
}


static void exc_inject_test(struct svm_test *test)
{
    asm volatile ("vmmcall\n\tvmmcall\n\t");
}

static bool exc_inject_finished(struct svm_test *test)
{
    switch (get_test_stage(test)) {
    case 0:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->save.rip += 3;
        vmcb->control.event_inj = NMI_VECTOR | SVM_EVTINJ_TYPE_EXEPT | SVM_EVTINJ_VALID;
        break;

    case 1:
        if (vmcb->control.exit_code != SVM_EXIT_ERR) {
            report(false, "VMEXIT not due to error. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        report(count_exc == 0, "exception with vector 2 not injected");
        vmcb->control.event_inj = DE_VECTOR | SVM_EVTINJ_TYPE_EXEPT | SVM_EVTINJ_VALID;
        break;

    case 2:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->save.rip += 3;
        report(count_exc == 1, "divide overflow exception injected");
        report(!(vmcb->control.event_inj & SVM_EVTINJ_VALID), "eventinj.VALID cleared");
        break;

    default:
        return true;
    }

    inc_test_stage(test);

    return get_test_stage(test) == 3;
}

static bool exc_inject_check(struct svm_test *test)
{
    return count_exc == 1 && get_test_stage(test) == 3;
}

static volatile bool virq_fired;

static void virq_isr(isr_regs_t *regs)
{
    virq_fired = true;
}

static void virq_inject_prepare(struct svm_test *test)
{
    handle_irq(0xf1, virq_isr);
    default_prepare(test);
    vmcb->control.int_ctl = V_INTR_MASKING_MASK | V_IRQ_MASK |
                            (0x0f << V_INTR_PRIO_SHIFT); // Set to the highest priority
    vmcb->control.int_vector = 0xf1;
    virq_fired = false;
    set_test_stage(test, 0);
}

static void virq_inject_test(struct svm_test *test)
{
    if (virq_fired) {
        report(false, "virtual interrupt fired before L2 sti");
        set_test_stage(test, -1);
        vmmcall();
    }

    irq_enable();
    asm volatile ("nop");
    irq_disable();

    if (!virq_fired) {
        report(false, "virtual interrupt not fired after L2 sti");
        set_test_stage(test, -1);
    }

    vmmcall();

    if (virq_fired) {
        report(false, "virtual interrupt fired before L2 sti after VINTR intercept");
        set_test_stage(test, -1);
        vmmcall();
    }

    irq_enable();
    asm volatile ("nop");
    irq_disable();

    if (!virq_fired) {
        report(false, "virtual interrupt not fired after return from VINTR intercept");
        set_test_stage(test, -1);
    }

    vmmcall();

    irq_enable();
    asm volatile ("nop");
    irq_disable();

    if (virq_fired) {
        report(false, "virtual interrupt fired when V_IRQ_PRIO less than V_TPR");
        set_test_stage(test, -1);
    }

    vmmcall();
    vmmcall();
}

static bool virq_inject_finished(struct svm_test *test)
{
    vmcb->save.rip += 3;

    switch (get_test_stage(test)) {
    case 0:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        if (vmcb->control.int_ctl & V_IRQ_MASK) {
            report(false, "V_IRQ not cleared on VMEXIT after firing");
            return true;
        }
        virq_fired = false;
        vmcb->control.intercept |= (1ULL << INTERCEPT_VINTR);
        vmcb->control.int_ctl = V_INTR_MASKING_MASK | V_IRQ_MASK |
                            (0x0f << V_INTR_PRIO_SHIFT);
        break;

    case 1:
        if (vmcb->control.exit_code != SVM_EXIT_VINTR) {
            report(false, "VMEXIT not due to vintr. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        if (virq_fired) {
            report(false, "V_IRQ fired before SVM_EXIT_VINTR");
            return true;
        }
        vmcb->control.intercept &= ~(1ULL << INTERCEPT_VINTR);
        break;

    case 2:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        virq_fired = false;
        // Set irq to lower priority
        vmcb->control.int_ctl = V_INTR_MASKING_MASK | V_IRQ_MASK |
                            (0x08 << V_INTR_PRIO_SHIFT);
        // Raise guest TPR
        vmcb->control.int_ctl |= 0x0a & V_TPR_MASK;
        break;

    case 3:
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        vmcb->control.intercept |= (1ULL << INTERCEPT_VINTR);
        break;

    case 4:
        // INTERCEPT_VINTR should be ignored because V_INTR_PRIO < V_TPR
        if (vmcb->control.exit_code != SVM_EXIT_VMMCALL) {
            report(false, "VMEXIT not due to vmmcall. Exit reason 0x%x",
                   vmcb->control.exit_code);
            return true;
        }
        break;

    default:
        return true;
    }

    inc_test_stage(test);

    return get_test_stage(test) == 5;
}

static bool virq_inject_check(struct svm_test *test)
{
    return get_test_stage(test) == 5;
}

/*
 * Detect nested guest RIP corruption as explained in kernel commit
 * b6162e82aef19fee9c32cb3fe9ac30d9116a8c73
 *
 * In the assembly loop below 'ins' is executed while IO instructions
 * are not intercepted; the instruction is emulated by L0.
 *
 * At the same time we are getting interrupts from the local APIC timer,
 * and we do intercept them in L1
 *
 * If the interrupt happens on the insb instruction, L0 will VMexit, emulate
 * the insb instruction and then it will inject the interrupt to L1 through
 * a nested VMexit.  Due to a bug, it would leave pre-emulation values of RIP,
 * RAX and RSP in the VMCB.
 *
 * In our intercept handler we detect the bug by checking that RIP is that of
 * the insb instruction, but its memory operand has already been written.
 * This means that insb was already executed.
 */

static volatile int isr_cnt = 0;
static volatile uint8_t io_port_var = 0xAA;
extern const char insb_instruction_label[];

static void reg_corruption_isr(isr_regs_t *regs)
{
    isr_cnt++;
    apic_write(APIC_EOI, 0);
}

static void reg_corruption_prepare(struct svm_test *test)
{
    default_prepare(test);
    set_test_stage(test, 0);

    vmcb->control.int_ctl = V_INTR_MASKING_MASK;
    vmcb->control.intercept |= (1ULL << INTERCEPT_INTR);

    handle_irq(TIMER_VECTOR, reg_corruption_isr);

    /* set local APIC to inject external interrupts */
    apic_write(APIC_TMICT, 0);
    apic_write(APIC_TDCR, 0);
    apic_write(APIC_LVTT, TIMER_VECTOR | APIC_LVT_TIMER_PERIODIC);
    apic_write(APIC_TMICT, 1000);
}

static void reg_corruption_test(struct svm_test *test)
{
    /* this is endless loop, which is interrupted by the timer interrupt */
    asm volatile (
            "1:\n\t"
            "movw $0x4d0, %%dx\n\t" // IO port
            "lea %[io_port_var], %%rdi\n\t"
            "movb $0xAA, %[io_port_var]\n\t"
            "insb_instruction_label:\n\t"
            "insb\n\t"
            "jmp 1b\n\t"

            : [io_port_var] "=m" (io_port_var)
            : /* no inputs*/
            : "rdx", "rdi"
    );
}

static bool reg_corruption_finished(struct svm_test *test)
{
    if (isr_cnt == 10000) {
        report(true,
               "No RIP corruption detected after %d timer interrupts",
               isr_cnt);
        set_test_stage(test, 1);
        return true;
    }

    if (vmcb->control.exit_code == SVM_EXIT_INTR) {

        void* guest_rip = (void*)vmcb->save.rip;

        irq_enable();
        asm volatile ("nop");
        irq_disable();

        if (guest_rip == insb_instruction_label && io_port_var != 0xAA) {
            report(false,
                   "RIP corruption detected after %d timer interrupts",
                   isr_cnt);
            return true;
        }

    }
    return false;
}

static bool reg_corruption_check(struct svm_test *test)
{
    return get_test_stage(test) == 1;
}

static void get_tss_entry(void *data)
{
    struct descriptor_table_ptr gdt;
    struct segment_desc64 *gdt_table;
    struct segment_desc64 *tss_entry;
    u16 tr = 0;

    sgdt(&gdt);
    tr = str();
    gdt_table = (struct segment_desc64 *) gdt.base;
    tss_entry = &gdt_table[tr / sizeof(struct segment_desc64)];
    *((struct segment_desc64 **)data) = tss_entry;
}

static int orig_cpu_count;

static void init_startup_prepare(struct svm_test *test)
{
    struct segment_desc64 *tss_entry;
    int i;

    vmcb_ident(vmcb);

    on_cpu(1, get_tss_entry, &tss_entry);

    orig_cpu_count = cpu_online_count;

    apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT,
                   id_map[1]);

    delay(100000000ULL);

    --cpu_online_count;

    *(uint64_t *)tss_entry &= ~DESC_BUSY;

    apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_STARTUP, id_map[1]);

    for (i = 0; i < 5 && cpu_online_count < orig_cpu_count; i++)
       delay(100000000ULL);
}

static bool init_startup_finished(struct svm_test *test)
{
    return true;
}

static bool init_startup_check(struct svm_test *test)
{
    return cpu_online_count == orig_cpu_count;
}

static volatile bool init_intercept;

static void init_intercept_prepare(struct svm_test *test)
{
    init_intercept = false;
    vmcb_ident(vmcb);
    vmcb->control.intercept |= (1ULL << INTERCEPT_INIT);
}

static void init_intercept_test(struct svm_test *test)
{
    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT, 0);
}

static bool init_intercept_finished(struct svm_test *test)
{
    vmcb->save.rip += 3;

    if (vmcb->control.exit_code != SVM_EXIT_INIT) {
        report(false, "VMEXIT not due to init intercept. Exit reason 0x%x",
               vmcb->control.exit_code);

        return true;
        }

    init_intercept = true;

    report(true, "INIT to vcpu intercepted");

    return true;
}

static bool init_intercept_check(struct svm_test *test)
{
    return init_intercept;
}

#define TEST(name) { #name, .v2 = name }

/*
 * v2 tests
 */

/*
 * Ensure that kvm recalculates the L1 guest's CPUID.01H:ECX.OSXSAVE
 * after VM-exit from an L2 guest that sets CR4.OSXSAVE to a different
 * value than in L1.
 */

static void svm_cr4_osxsave_test_guest(struct svm_test *test)
{
	write_cr4(read_cr4() & ~X86_CR4_OSXSAVE);
}

static void svm_cr4_osxsave_test(void)
{
	if (!this_cpu_has(X86_FEATURE_XSAVE)) {
		report_skip("XSAVE not detected");
		return;
	}

	if (!(read_cr4() & X86_CR4_OSXSAVE)) {
		unsigned long cr4 = read_cr4() | X86_CR4_OSXSAVE;

		write_cr4(cr4);
		vmcb->save.cr4 = cr4;
	}

	report(cpuid_osxsave(), "CPUID.01H:ECX.XSAVE set before VMRUN");

	test_set_guest(svm_cr4_osxsave_test_guest);
	report(svm_vmrun() == SVM_EXIT_VMMCALL,
	       "svm_cr4_osxsave_test_guest finished with VMMCALL");

	report(cpuid_osxsave(), "CPUID.01H:ECX.XSAVE set after VMRUN");
}

static void basic_guest_main(struct svm_test *test)
{
}


#define SVM_TEST_REG_RESERVED_BITS(start, end, inc, str_name, reg, val,	\
				   resv_mask)				\
{									\
        u64 tmp, mask;							\
        int i;								\
									\
        for (i = start; i <= end; i = i + inc) {			\
                mask = 1ull << i;					\
                if (!(mask & resv_mask))				\
                        continue;					\
                tmp = val | mask;					\
		reg = tmp;						\
		report(svm_vmrun() == SVM_EXIT_ERR, "Test %s %d:%d: %lx",\
		    str_name, end, start, tmp);				\
        }								\
}

#define SVM_TEST_CR_RESERVED_BITS(start, end, inc, cr, val, resv_mask,	\
				  exit_code, test_name)			\
{									\
	u64 tmp, mask;							\
	int i;								\
									\
	for (i = start; i <= end; i = i + inc) {			\
		mask = 1ull << i;					\
		if (!(mask & resv_mask))				\
			continue;					\
		tmp = val | mask;					\
		switch (cr) {						\
		case 0:							\
			vmcb->save.cr0 = tmp;				\
			break;						\
		case 3:							\
			vmcb->save.cr3 = tmp;				\
			break;						\
		case 4:							\
			vmcb->save.cr4 = tmp;				\
		}							\
		report(svm_vmrun() == exit_code, "Test CR%d " test_name "%d:%d: %lx",\
		    cr, end, start, tmp);				\
	}								\
}

static void test_efer(void)
{
	/*
	 * Un-setting EFER.SVME is illegal
	 */
	u64 efer_saved = vmcb->save.efer;
	u64 efer = efer_saved;

	report (svm_vmrun() == SVM_EXIT_VMMCALL, "EFER.SVME: %lx", efer);
	efer &= ~EFER_SVME;
	vmcb->save.efer = efer;
	report (svm_vmrun() == SVM_EXIT_ERR, "EFER.SVME: %lx", efer);
	vmcb->save.efer = efer_saved;

	/*
	 * EFER MBZ bits: 63:16, 9
	 */
	efer_saved = vmcb->save.efer;

	SVM_TEST_REG_RESERVED_BITS(8, 9, 1, "EFER", vmcb->save.efer,
	    efer_saved, SVM_EFER_RESERVED_MASK);
	SVM_TEST_REG_RESERVED_BITS(16, 63, 4, "EFER", vmcb->save.efer,
	    efer_saved, SVM_EFER_RESERVED_MASK);

	/*
	 * EFER.LME and CR0.PG are both set and CR4.PAE is zero.
	 */
	u64 cr0_saved = vmcb->save.cr0;
	u64 cr0;
	u64 cr4_saved = vmcb->save.cr4;
	u64 cr4;

	efer = efer_saved | EFER_LME;
	vmcb->save.efer = efer;
	cr0 = cr0_saved | X86_CR0_PG | X86_CR0_PE;
	vmcb->save.cr0 = cr0;
	cr4 = cr4_saved & ~X86_CR4_PAE;
	vmcb->save.cr4 = cr4;
	report(svm_vmrun() == SVM_EXIT_ERR, "EFER.LME=1 (%lx), "
	    "CR0.PG=1 (%lx) and CR4.PAE=0 (%lx)", efer, cr0, cr4);

	/*
	 * EFER.LME and CR0.PG are both set and CR0.PE is zero.
	 */
	vmcb->save.cr4 = cr4_saved | X86_CR4_PAE;
	cr0 &= ~X86_CR0_PE;
	vmcb->save.cr0 = cr0;
	report(svm_vmrun() == SVM_EXIT_ERR, "EFER.LME=1 (%lx), "
	    "CR0.PG=1 and CR0.PE=0 (%lx)", efer, cr0);

	/*
	 * EFER.LME, CR0.PG, CR4.PAE, CS.L, and CS.D are all non-zero.
	 */
	u32 cs_attrib_saved = vmcb->save.cs.attrib;
	u32 cs_attrib;

	cr0 |= X86_CR0_PE;
	vmcb->save.cr0 = cr0;
	cs_attrib = cs_attrib_saved | SVM_SELECTOR_L_MASK |
	    SVM_SELECTOR_DB_MASK;
	vmcb->save.cs.attrib = cs_attrib;
	report(svm_vmrun() == SVM_EXIT_ERR, "EFER.LME=1 (%lx), "
	    "CR0.PG=1 (%lx), CR4.PAE=1 (%lx), CS.L=1 and CS.D=1 (%x)",
	    efer, cr0, cr4, cs_attrib);

	vmcb->save.cr0 = cr0_saved;
	vmcb->save.cr4 = cr4_saved;
	vmcb->save.efer = efer_saved;
	vmcb->save.cs.attrib = cs_attrib_saved;
}

static void test_cr0(void)
{
	/*
	 * Un-setting CR0.CD and setting CR0.NW is illegal combination
	 */
	u64 cr0_saved = vmcb->save.cr0;
	u64 cr0 = cr0_saved;

	cr0 |= X86_CR0_CD;
	cr0 &= ~X86_CR0_NW;
	vmcb->save.cr0 = cr0;
	report (svm_vmrun() == SVM_EXIT_VMMCALL, "Test CR0 CD=1,NW=0: %lx",
	    cr0);
	cr0 |= X86_CR0_NW;
	vmcb->save.cr0 = cr0;
	report (svm_vmrun() == SVM_EXIT_VMMCALL, "Test CR0 CD=1,NW=1: %lx",
	    cr0);
	cr0 &= ~X86_CR0_NW;
	cr0 &= ~X86_CR0_CD;
	vmcb->save.cr0 = cr0;
	report (svm_vmrun() == SVM_EXIT_VMMCALL, "Test CR0 CD=0,NW=0: %lx",
	    cr0);
	cr0 |= X86_CR0_NW;
	vmcb->save.cr0 = cr0;
	report (svm_vmrun() == SVM_EXIT_ERR, "Test CR0 CD=0,NW=1: %lx",
	    cr0);
	vmcb->save.cr0 = cr0_saved;

	/*
	 * CR0[63:32] are not zero
	 */
	cr0 = cr0_saved;

	SVM_TEST_REG_RESERVED_BITS(32, 63, 4, "CR0", vmcb->save.cr0, cr0_saved,
	    SVM_CR0_RESERVED_MASK);
	vmcb->save.cr0 = cr0_saved;
}

static void test_cr3(void)
{
	/*
	 * CR3 MBZ bits based on different modes:
	 *   [63:52] - long mode
	 */
	u64 cr3_saved = vmcb->save.cr3;

	SVM_TEST_CR_RESERVED_BITS(0, 63, 1, 3, cr3_saved,
	    SVM_CR3_LONG_MBZ_MASK, SVM_EXIT_ERR, "");

	vmcb->save.cr3 = cr3_saved & ~SVM_CR3_LONG_MBZ_MASK;
	report(svm_vmrun() == SVM_EXIT_VMMCALL, "Test CR3 63:0: %lx",
	    vmcb->save.cr3);

	/*
	 * CR3 non-MBZ reserved bits based on different modes:
	 *   [11:5] [2:0] - long mode (PCIDE=0)
	 *          [2:0] - PAE legacy mode
	 */
	u64 cr4_saved = vmcb->save.cr4;
	u64 *pdpe = npt_get_pml4e();

	/*
	 * Long mode
	 */
	if (this_cpu_has(X86_FEATURE_PCID)) {
		vmcb->save.cr4 = cr4_saved | X86_CR4_PCIDE;
		SVM_TEST_CR_RESERVED_BITS(0, 11, 1, 3, cr3_saved,
		    SVM_CR3_LONG_RESERVED_MASK, SVM_EXIT_VMMCALL, "(PCIDE=1) ");

		vmcb->save.cr3 = cr3_saved & ~SVM_CR3_LONG_RESERVED_MASK;
		report(svm_vmrun() == SVM_EXIT_VMMCALL, "Test CR3 63:0: %lx",
		    vmcb->save.cr3);
	}

	vmcb->save.cr4 = cr4_saved & ~X86_CR4_PCIDE;

	/* Clear P (Present) bit in NPT in order to trigger #NPF */
	pdpe[0] &= ~1ULL;

	SVM_TEST_CR_RESERVED_BITS(0, 11, 1, 3, cr3_saved,
	    SVM_CR3_LONG_RESERVED_MASK, SVM_EXIT_NPF, "(PCIDE=0) ");

	pdpe[0] |= 1ULL;
	vmcb->save.cr3 = cr3_saved;

	/*
	 * PAE legacy
	 */
	pdpe[0] &= ~1ULL;
	vmcb->save.cr4 = cr4_saved | X86_CR4_PAE;
	SVM_TEST_CR_RESERVED_BITS(0, 2, 1, 3, cr3_saved,
	    SVM_CR3_PAE_LEGACY_RESERVED_MASK, SVM_EXIT_NPF, "(PAE) ");

	pdpe[0] |= 1ULL;
	vmcb->save.cr3 = cr3_saved;
	vmcb->save.cr4 = cr4_saved;
}

static void test_cr4(void)
{
	/*
	 * CR4 MBZ bits based on different modes:
	 *   [15:12], 17, 19, [31:22] - legacy mode
	 *   [15:12], 17, 19, [63:22] - long mode
	 */
	u64 cr4_saved = vmcb->save.cr4;
	u64 efer_saved = vmcb->save.efer;
	u64 efer = efer_saved;

	efer &= ~EFER_LME;
	vmcb->save.efer = efer;
	SVM_TEST_CR_RESERVED_BITS(12, 31, 1, 4, cr4_saved,
	    SVM_CR4_LEGACY_RESERVED_MASK, SVM_EXIT_ERR, "");

	efer |= EFER_LME;
	vmcb->save.efer = efer;
	SVM_TEST_CR_RESERVED_BITS(12, 31, 1, 4, cr4_saved,
	    SVM_CR4_RESERVED_MASK, SVM_EXIT_ERR, "");
	SVM_TEST_CR_RESERVED_BITS(32, 63, 4, 4, cr4_saved,
	    SVM_CR4_RESERVED_MASK, SVM_EXIT_ERR, "");

	vmcb->save.cr4 = cr4_saved;
	vmcb->save.efer = efer_saved;
}

static void test_dr(void)
{
	/*
	 * DR6[63:32] and DR7[63:32] are MBZ
	 */
	u64 dr_saved = vmcb->save.dr6;

	SVM_TEST_REG_RESERVED_BITS(32, 63, 4, "DR6", vmcb->save.dr6, dr_saved,
	    SVM_DR6_RESERVED_MASK);
	vmcb->save.dr6 = dr_saved;

	dr_saved = vmcb->save.dr7;
	SVM_TEST_REG_RESERVED_BITS(32, 63, 4, "DR7", vmcb->save.dr7, dr_saved,
	    SVM_DR7_RESERVED_MASK);

	vmcb->save.dr7 = dr_saved;
}

static void svm_guest_state_test(void)
{
	test_set_guest(basic_guest_main);

	test_efer();
	test_cr0();
	test_cr3();
	test_cr4();
	test_dr();
}


static bool volatile svm_errata_reproduced = false;
static unsigned long volatile physical = 0;


/*
 *
 * Test the following errata:
 * If the VMRUN/VMSAVE/VMLOAD are attempted by the nested guest,
 * the CPU would first check the EAX against host reserved memory
 * regions (so far only SMM_ADDR/SMM_MASK are known to cause it),
 * and only then signal #VMexit
 *
 * Try to reproduce this by trying vmsave on each possible 4K aligned memory
 * address in the low 4G where the SMM area has to reside.
 */

static void gp_isr(struct ex_regs *r)
{
    svm_errata_reproduced = true;
    /* skip over the vmsave instruction*/
    r->rip += 3;
}

static void svm_vmrun_errata_test(void)
{
    unsigned long *last_page = NULL;

    handle_exception(GP_VECTOR, gp_isr);

    while (!svm_errata_reproduced) {

        unsigned long *page = alloc_pages(1);

        if (!page) {
            report(true, "All guest memory tested, no bug found");;
            break;
        }

        physical = virt_to_phys(page);

        asm volatile (
            "mov %[_physical], %%rax\n\t"
            "vmsave %%rax\n\t"

            : [_physical] "=m" (physical)
            : /* no inputs*/
            : "rax" /*clobbers*/
        );

        if (svm_errata_reproduced) {
            report(false, "Got #GP exception - svm errata reproduced at 0x%lx",
                   physical);
            break;
        }

        *page = (unsigned long)last_page;
        last_page = page;
    }

    while (last_page) {
        unsigned long *page = last_page;
        last_page = (unsigned long *)*last_page;
        free_pages_by_order(page, 1);
    }
}

struct svm_test svm_tests[] = {
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
    { "rsm", default_supported,
      prepare_rsm_intercept, default_prepare_gif_clear,
      test_rsm_intercept, finished_rsm_intercept, check_rsm_intercept },
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
    { "npt_np", npt_supported, npt_np_prepare,
      default_prepare_gif_clear, npt_np_test,
      default_finished, npt_np_check },
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
    { "tsc_adjust", tsc_adjust_supported, tsc_adjust_prepare,
      default_prepare_gif_clear, tsc_adjust_test,
      default_finished, tsc_adjust_check },
    { "latency_run_exit", default_supported, latency_prepare,
      default_prepare_gif_clear, latency_test,
      latency_finished, latency_check },
    { "latency_svm_insn", default_supported, lat_svm_insn_prepare,
      default_prepare_gif_clear, null_test,
      lat_svm_insn_finished, lat_svm_insn_check },
    { "exc_inject", default_supported, exc_inject_prepare,
      default_prepare_gif_clear, exc_inject_test,
      exc_inject_finished, exc_inject_check },
    { "pending_event", default_supported, pending_event_prepare,
      default_prepare_gif_clear,
      pending_event_test, pending_event_finished, pending_event_check },
    { "pending_event_cli", default_supported, pending_event_cli_prepare,
      pending_event_cli_prepare_gif_clear,
      pending_event_cli_test, pending_event_cli_finished,
      pending_event_cli_check },
    { "interrupt", default_supported, interrupt_prepare,
      default_prepare_gif_clear, interrupt_test,
      interrupt_finished, interrupt_check },
    { "nmi", default_supported, nmi_prepare,
      default_prepare_gif_clear, nmi_test,
      nmi_finished, nmi_check },
    { "nmi_hlt", smp_supported, nmi_prepare,
      default_prepare_gif_clear, nmi_hlt_test,
      nmi_hlt_finished, nmi_hlt_check },
    { "virq_inject", default_supported, virq_inject_prepare,
      default_prepare_gif_clear, virq_inject_test,
      virq_inject_finished, virq_inject_check },
    { "reg_corruption", default_supported, reg_corruption_prepare,
      default_prepare_gif_clear, reg_corruption_test,
      reg_corruption_finished, reg_corruption_check },
    { "svm_init_startup_test", smp_supported, init_startup_prepare,
      default_prepare_gif_clear, null_test,
      init_startup_finished, init_startup_check },
    { "svm_init_intercept_test", smp_supported, init_intercept_prepare,
      default_prepare_gif_clear, init_intercept_test,
      init_intercept_finished, init_intercept_check, .on_vcpu = 2 },
    TEST(svm_cr4_osxsave_test),
    TEST(svm_guest_state_test),
    TEST(svm_vmrun_errata_test),
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};
