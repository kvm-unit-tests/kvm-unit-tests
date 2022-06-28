/*
 * Framework for testing nested virtualization
 */

#include "svm.h"
#include "libcflat.h"
#include "processor.h"
#include "desc.h"
#include "msr.h"
#include "vm.h"
#include "fwcfg.h"
#include "smp.h"
#include "types.h"
#include "alloc_page.h"
#include "isr.h"
#include "apic.h"

/* for the nested page table*/
u64 *pml4e;

struct vmcb *vmcb;

u64 *npt_get_pte(u64 address)
{
	return get_pte(npt_get_pml4e(), (void*)address);
}

u64 *npt_get_pde(u64 address)
{
	struct pte_search search;
	search = find_pte_level(npt_get_pml4e(), (void*)address, 2);
	return search.pte;
}

u64 *npt_get_pdpe(u64 address)
{
	struct pte_search search;
	search = find_pte_level(npt_get_pml4e(), (void*)address, 3);
	return search.pte;
}

u64 *npt_get_pml4e(void)
{
	return pml4e;
}

bool smp_supported(void)
{
	return cpu_count() > 1;
}

bool default_supported(void)
{
    return true;
}

bool vgif_supported(void)
{
	return this_cpu_has(X86_FEATURE_VGIF);
}

bool lbrv_supported(void)
{
    return this_cpu_has(X86_FEATURE_LBRV);
}

bool tsc_scale_supported(void)
{
    return this_cpu_has(X86_FEATURE_TSCRATEMSR);
}

bool pause_filter_supported(void)
{
    return this_cpu_has(X86_FEATURE_PAUSEFILTER);
}

bool pause_threshold_supported(void)
{
    return this_cpu_has(X86_FEATURE_PFTHRESHOLD);
}


void default_prepare(struct svm_test *test)
{
	vmcb_ident(vmcb);
}

void default_prepare_gif_clear(struct svm_test *test)
{
}

bool default_finished(struct svm_test *test)
{
	return true; /* one vmexit */
}

bool npt_supported(void)
{
	return this_cpu_has(X86_FEATURE_NPT);
}

int get_test_stage(struct svm_test *test)
{
	barrier();
	return test->scratch;
}

void set_test_stage(struct svm_test *test, int s)
{
	barrier();
	test->scratch = s;
	barrier();
}

void inc_test_stage(struct svm_test *test)
{
	barrier();
	test->scratch++;
	barrier();
}

static void vmcb_set_seg(struct vmcb_seg *seg, u16 selector,
                         u64 base, u32 limit, u32 attr)
{
	seg->selector = selector;
	seg->attrib = attr;
	seg->limit = limit;
	seg->base = base;
}

inline void vmmcall(void)
{
	asm volatile ("vmmcall" : : : "memory");
}

static test_guest_func guest_main;

void test_set_guest(test_guest_func func)
{
	guest_main = func;
}

static void test_thunk(struct svm_test *test)
{
	guest_main(test);
	vmmcall();
}

u8 *io_bitmap;
u8 io_bitmap_area[16384];

u8 *msr_bitmap;
u8 msr_bitmap_area[MSR_BITMAP_SIZE + PAGE_SIZE];

void vmcb_ident(struct vmcb *vmcb)
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
	ctrl->intercept = (1ULL << INTERCEPT_VMRUN) |
			  (1ULL << INTERCEPT_VMMCALL) |
			  (1ULL << INTERCEPT_SHUTDOWN);
	ctrl->iopm_base_pa = virt_to_phys(io_bitmap);
	ctrl->msrpm_base_pa = virt_to_phys(msr_bitmap);

	if (npt_supported()) {
		ctrl->nested_ctl = 1;
		ctrl->nested_cr3 = (u64)pml4e;
		ctrl->tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	}
}

struct regs regs;

struct regs get_regs(void)
{
	return regs;
}

// rax handled specially below


struct svm_test *v2_test;


u64 guest_stack[10000];

int __svm_vmrun(u64 rip)
{
	vmcb->save.rip = (ulong)rip;
	vmcb->save.rsp = (ulong)(guest_stack + ARRAY_SIZE(guest_stack));
	regs.rdi = (ulong)v2_test;

	asm volatile (
		ASM_PRE_VMRUN_CMD
                "vmrun %%rax\n\t"               \
		ASM_POST_VMRUN_CMD
		:
		: "a" (virt_to_phys(vmcb))
		: "memory", "r15");

	return (vmcb->control.exit_code);
}

int svm_vmrun(void)
{
	return __svm_vmrun((u64)test_thunk);
}

extern u8 vmrun_rip;

static noinline void test_run(struct svm_test *test)
{
	u64 vmcb_phys = virt_to_phys(vmcb);

	irq_disable();
	vmcb_ident(vmcb);

	test->prepare(test);
	guest_main = test->guest_func;
	vmcb->save.rip = (ulong)test_thunk;
	vmcb->save.rsp = (ulong)(guest_stack + ARRAY_SIZE(guest_stack));
	regs.rdi = (ulong)test;
	do {
		struct svm_test *the_test = test;
		u64 the_vmcb = vmcb_phys;
		asm volatile (
			"clgi;\n\t" // semi-colon needed for LLVM compatibility
			"sti \n\t"
			"call *%c[PREPARE_GIF_CLEAR](%[test]) \n \t"
			"mov %[vmcb_phys], %%rax \n\t"
			ASM_PRE_VMRUN_CMD
			".global vmrun_rip\n\t"		\
			"vmrun_rip: vmrun %%rax\n\t"    \
			ASM_POST_VMRUN_CMD
			"cli \n\t"
			"stgi"
			: // inputs clobbered by the guest:
			"=D" (the_test),            // first argument register
			"=b" (the_vmcb)             // callee save register!
			: [test] "0" (the_test),
			[vmcb_phys] "1"(the_vmcb),
			[PREPARE_GIF_CLEAR] "i" (offsetof(struct svm_test, prepare_gif_clear))
			: "rax", "rcx", "rdx", "rsi",
			"r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15",
			"memory");
		++test->exits;
	} while (!test->finished(test));
	irq_enable();

	report(test->succeeded(test), "%s", test->name);

        if (test->on_vcpu)
	    test->on_vcpu_done = true;
}

static void set_additional_vcpu_msr(void *msr_efer)
{
	void *hsave = alloc_page();

	wrmsr(MSR_VM_HSAVE_PA, virt_to_phys(hsave));
	wrmsr(MSR_EFER, (ulong)msr_efer | EFER_SVME);
}

static void setup_npt(void)
{
	u64 size = fwcfg_get_u64(FW_CFG_RAM_SIZE);

	/* Ensure all <4gb is mapped, e.g. if there's no RAM above 4gb. */
	if (size < BIT_ULL(32))
		size = BIT_ULL(32);

	pml4e = alloc_page();

	/* NPT accesses are treated as "user" accesses. */
	__setup_mmu_range(pml4e, 0, size, X86_MMU_MAP_USER);
}

static void setup_svm(void)
{
	void *hsave = alloc_page();
	int i;

	wrmsr(MSR_VM_HSAVE_PA, virt_to_phys(hsave));
	wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SVME);

	io_bitmap = (void *) ALIGN((ulong)io_bitmap_area, PAGE_SIZE);

	msr_bitmap = (void *) ALIGN((ulong)msr_bitmap_area, PAGE_SIZE);

	if (!npt_supported())
		return;

	for (i = 1; i < cpu_count(); i++)
		on_cpu(i, (void *)set_additional_vcpu_msr, (void *)rdmsr(MSR_EFER));

	printf("NPT detected - running all tests with NPT enabled\n");

	/*
	* Nested paging supported - Build a nested page table
	* Build the page-table bottom-up and map everything with 4k
	* pages to get enough granularity for the NPT unit-tests.
	*/

	setup_npt();
}

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

int run_svm_tests(int ac, char **av, struct svm_test *svm_tests)
{
	int i = 0;

	ac--;
	av++;

	if (!this_cpu_has(X86_FEATURE_SVM)) {
		printf("SVM not available\n");
		return report_summary();
	}

	setup_svm();

	vmcb = alloc_page();

	for (; svm_tests[i].name != NULL; i++) {
		if (!test_wanted(svm_tests[i].name, av, ac))
			continue;
		if (svm_tests[i].supported && !svm_tests[i].supported())
			continue;
		if (svm_tests[i].v2 == NULL) {
			if (svm_tests[i].on_vcpu) {
				if (cpu_count() <= svm_tests[i].on_vcpu)
					continue;
				on_cpu_async(svm_tests[i].on_vcpu, (void *)test_run, &svm_tests[i]);
				while (!svm_tests[i].on_vcpu_done)
					cpu_relax();
			}
			else
				test_run(&svm_tests[i]);
		} else {
			vmcb_ident(vmcb);
			v2_test = &(svm_tests[i]);
			svm_tests[i].v2();
		}
	}

	if (!matched)
		report(matched, "command line didn't match any tests!");

	return report_summary();
}
