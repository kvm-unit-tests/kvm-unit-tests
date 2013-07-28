#include "libcflat.h"
#include "processor.h"
#include "vm.h"
#include "desc.h"
#include "vmx.h"
#include "msr.h"
#include "smp.h"
#include "io.h"

int fails = 0, tests = 0;
u32 *vmxon_region;
struct vmcs *vmcs_root;
u32 vpid_cnt;
void *guest_stack, *guest_syscall_stack;
u32 ctrl_pin, ctrl_enter, ctrl_exit, ctrl_cpu[2];
ulong fix_cr0_set, fix_cr0_clr;
ulong fix_cr4_set, fix_cr4_clr;
struct regs regs;
struct vmx_test *current;
u64 hypercall_field = 0;
bool launched;

extern u64 gdt64_desc[];
extern u64 idt_descr[];
extern u64 tss_descr[];
extern void *vmx_return;
extern void *entry_sysenter;
extern void *guest_entry;

static void report(const char *name, int result)
{
	++tests;
	if (result)
		printf("PASS: %s\n", name);
	else {
		printf("FAIL: %s\n", name);
		++fails;
	}
}

static int make_vmcs_current(struct vmcs *vmcs)
{
	bool ret;

	asm volatile ("vmptrld %1; setbe %0" : "=q" (ret) : "m" (vmcs) : "cc");
	return ret;
}

/* entry_sysenter */
asm(
	".align	4, 0x90\n\t"
	".globl	entry_sysenter\n\t"
	"entry_sysenter:\n\t"
	SAVE_GPR
	"	and	$0xf, %rax\n\t"
	"	mov	%rax, %rdi\n\t"
	"	call	syscall_handler\n\t"
	LOAD_GPR
	"	vmresume\n\t"
);

static void __attribute__((__used__)) syscall_handler(u64 syscall_no)
{
	current->syscall_handler(syscall_no);
}

static inline int vmx_on()
{
	bool ret;
	asm volatile ("vmxon %1; setbe %0\n\t"
		: "=q"(ret) : "m"(vmxon_region) : "cc");
	return ret;
}

static inline int vmx_off()
{
	bool ret;
	asm volatile("vmxoff; setbe %0\n\t"
		: "=q"(ret) : : "cc");
	return ret;
}

static void print_vmexit_info()
{
	u64 guest_rip, guest_rsp;
	ulong reason = vmcs_read(EXI_REASON) & 0xff;
	ulong exit_qual = vmcs_read(EXI_QUALIFICATION);
	guest_rip = vmcs_read(GUEST_RIP);
	guest_rsp = vmcs_read(GUEST_RSP);
	printf("VMEXIT info:\n");
	printf("\tvmexit reason = %d\n", reason);
	printf("\texit qualification = 0x%x\n", exit_qual);
	printf("\tBit 31 of reason = %x\n", (vmcs_read(EXI_REASON) >> 31) & 1);
	printf("\tguest_rip = 0x%llx\n", guest_rip);
	printf("\tRAX=0x%llx    RBX=0x%llx    RCX=0x%llx    RDX=0x%llx\n",
		regs.rax, regs.rbx, regs.rcx, regs.rdx);
	printf("\tRSP=0x%llx    RBP=0x%llx    RSI=0x%llx    RDI=0x%llx\n",
		guest_rsp, regs.rbp, regs.rsi, regs.rdi);
	printf("\tR8 =0x%llx    R9 =0x%llx    R10=0x%llx    R11=0x%llx\n",
		regs.r8, regs.r9, regs.r10, regs.r11);
	printf("\tR12=0x%llx    R13=0x%llx    R14=0x%llx    R15=0x%llx\n",
		regs.r12, regs.r13, regs.r14, regs.r15);
}

static void test_vmclear(void)
{
	u64 rflags;

	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	report("test vmclear", vmcs_clear(vmcs_root) == 0);
}

static void test_vmxoff(void)
{
	int ret;
	u64 rflags;

	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	ret = vmx_off();
	report("test vmxoff", !ret);
}

static void __attribute__((__used__)) guest_main(void)
{
	current->guest_main();
}

/* guest_entry */
asm(
	".align	4, 0x90\n\t"
	".globl	entry_guest\n\t"
	"guest_entry:\n\t"
	"	call guest_main\n\t"
	"	mov $1, %edi\n\t"
	"	call hypercall\n\t"
);

static void init_vmcs_ctrl(void)
{
	/* 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA */
	/* 26.2.1.1 */
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	/* Disable VMEXIT of IO instruction */
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	if (ctrl_cpu_rev[0].set & CPU_SECONDARY) {
		ctrl_cpu[1] |= ctrl_cpu_rev[1].set & ctrl_cpu_rev[1].clr;
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	}
	vmcs_write(CR3_TARGET_COUNT, 0);
	vmcs_write(VPID, ++vpid_cnt);
}

static void init_vmcs_host(void)
{
	/* 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA */
	/* 26.2.1.2 */
	vmcs_write(HOST_EFER, rdmsr(MSR_EFER));

	/* 26.2.1.3 */
	vmcs_write(ENT_CONTROLS, ctrl_enter);
	vmcs_write(EXI_CONTROLS, ctrl_exit);

	/* 26.2.2 */
	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, read_cr3());
	vmcs_write(HOST_CR4, read_cr4());
	vmcs_write(HOST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(HOST_SYSENTER_CS,  SEL_KERN_CODE_64);

	/* 26.2.3 */
	vmcs_write(HOST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(HOST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_FS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_GS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_TR, SEL_TSS_RUN);
	vmcs_write(HOST_BASE_TR,   (u64)tss_descr);
	vmcs_write(HOST_BASE_GDTR, (u64)gdt64_desc);
	vmcs_write(HOST_BASE_IDTR, (u64)idt_descr);
	vmcs_write(HOST_BASE_FS, 0);
	vmcs_write(HOST_BASE_GS, 0);

	/* Set other vmcs area */
	vmcs_write(PF_ERROR_MASK, 0);
	vmcs_write(PF_ERROR_MATCH, 0);
	vmcs_write(VMCS_LINK_PTR, ~0ul);
	vmcs_write(VMCS_LINK_PTR_HI, ~0ul);
	vmcs_write(HOST_RIP, (u64)(&vmx_return));
}

static void init_vmcs_guest(void)
{
	/* 26.3 CHECKING AND LOADING GUEST STATE */
	ulong guest_cr0, guest_cr4, guest_cr3;
	/* 26.3.1.1 */
	guest_cr0 = read_cr0();
	guest_cr4 = read_cr4();
	guest_cr3 = read_cr3();
	if (ctrl_enter & ENT_GUEST_64) {
		guest_cr0 |= X86_CR0_PG;
		guest_cr4 |= X86_CR4_PAE;
	}
	if ((ctrl_enter & ENT_GUEST_64) == 0)
		guest_cr4 &= (~X86_CR4_PCIDE);
	if (guest_cr0 & X86_CR0_PG)
		guest_cr0 |= X86_CR0_PE;
	vmcs_write(GUEST_CR0, guest_cr0);
	vmcs_write(GUEST_CR3, guest_cr3);
	vmcs_write(GUEST_CR4, guest_cr4);
	vmcs_write(GUEST_SYSENTER_CS,  SEL_KERN_CODE_64);
	vmcs_write(GUEST_SYSENTER_ESP,
		(u64)(guest_syscall_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(GUEST_DR7, 0);
	vmcs_write(GUEST_EFER, rdmsr(MSR_EFER));

	/* 26.3.1.2 */
	vmcs_write(GUEST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(GUEST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_FS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_GS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_TR, SEL_TSS_RUN);
	vmcs_write(GUEST_SEL_LDTR, 0);

	vmcs_write(GUEST_BASE_CS, 0);
	vmcs_write(GUEST_BASE_ES, 0);
	vmcs_write(GUEST_BASE_SS, 0);
	vmcs_write(GUEST_BASE_DS, 0);
	vmcs_write(GUEST_BASE_FS, 0);
	vmcs_write(GUEST_BASE_GS, 0);
	vmcs_write(GUEST_BASE_TR,   (u64)tss_descr);
	vmcs_write(GUEST_BASE_LDTR, 0);

	vmcs_write(GUEST_LIMIT_CS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_DS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_ES, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_SS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_FS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_GS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_LDTR, 0xffff);
	vmcs_write(GUEST_LIMIT_TR, ((struct descr *)tss_descr)->limit);

	vmcs_write(GUEST_AR_CS, 0xa09b);
	vmcs_write(GUEST_AR_DS, 0xc093);
	vmcs_write(GUEST_AR_ES, 0xc093);
	vmcs_write(GUEST_AR_FS, 0xc093);
	vmcs_write(GUEST_AR_GS, 0xc093);
	vmcs_write(GUEST_AR_SS, 0xc093);
	vmcs_write(GUEST_AR_LDTR, 0x82);
	vmcs_write(GUEST_AR_TR, 0x8b);

	/* 26.3.1.3 */
	vmcs_write(GUEST_BASE_GDTR, (u64)gdt64_desc);
	vmcs_write(GUEST_BASE_IDTR, (u64)idt_descr);
	vmcs_write(GUEST_LIMIT_GDTR,
		((struct descr *)gdt64_desc)->limit & 0xffff);
	vmcs_write(GUEST_LIMIT_IDTR,
		((struct descr *)idt_descr)->limit & 0xffff);

	/* 26.3.1.4 */
	vmcs_write(GUEST_RIP, (u64)(&guest_entry));
	vmcs_write(GUEST_RSP, (u64)(guest_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_RFLAGS, 0x2);

	/* 26.3.1.5 */
	vmcs_write(GUEST_ACTV_STATE, 0);
	vmcs_write(GUEST_INTR_STATE, 0);
}

static int init_vmcs(struct vmcs **vmcs)
{
	*vmcs = alloc_page();
	memset(*vmcs, 0, PAGE_SIZE);
	(*vmcs)->revision_id = basic.revision;
	/* vmclear first to init vmcs */
	if (vmcs_clear(*vmcs)) {
		printf("%s : vmcs_clear error\n", __func__);
		return 1;
	}

	if (make_vmcs_current(*vmcs)) {
		printf("%s : make_vmcs_current error\n", __func__);
		return 1;
	}

	/* All settings to pin/exit/enter/cpu
	   control fields should be placed here */
	ctrl_pin |= PIN_EXTINT | PIN_NMI | PIN_VIRT_NMI;
	ctrl_exit = EXI_LOAD_EFER | EXI_HOST_64;
	ctrl_enter = (ENT_LOAD_EFER | ENT_GUEST_64);
	ctrl_cpu[0] |= CPU_HLT;
	/* DIsable IO instruction VMEXIT now */
	ctrl_cpu[0] &= (~(CPU_IO | CPU_IO_BITMAP));
	ctrl_cpu[1] = 0;

	ctrl_pin = (ctrl_pin | ctrl_pin_rev.set) & ctrl_pin_rev.clr;
	ctrl_enter = (ctrl_enter | ctrl_enter_rev.set) & ctrl_enter_rev.clr;
	ctrl_exit = (ctrl_exit | ctrl_exit_rev.set) & ctrl_exit_rev.clr;
	ctrl_cpu[0] = (ctrl_cpu[0] | ctrl_cpu_rev[0].set) & ctrl_cpu_rev[0].clr;

	init_vmcs_ctrl();
	init_vmcs_host();
	init_vmcs_guest();
	return 0;
}

static void init_vmx(void)
{
	vmxon_region = alloc_page();
	memset(vmxon_region, 0, PAGE_SIZE);

	fix_cr0_set =  rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	fix_cr0_clr =  rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	fix_cr4_set =  rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	fix_cr4_clr = rdmsr(MSR_IA32_VMX_CR4_FIXED1);
	basic.val = rdmsr(MSR_IA32_VMX_BASIC);
	ctrl_pin_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PIN
			: MSR_IA32_VMX_PINBASED_CTLS);
	ctrl_exit_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_EXIT
			: MSR_IA32_VMX_EXIT_CTLS);
	ctrl_enter_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_ENTRY
			: MSR_IA32_VMX_ENTRY_CTLS);
	ctrl_cpu_rev[0].val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PROC
			: MSR_IA32_VMX_PROCBASED_CTLS);
	if (ctrl_cpu_rev[0].set & CPU_SECONDARY)
		ctrl_cpu_rev[1].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if (ctrl_cpu_rev[1].set & CPU_EPT || ctrl_cpu_rev[1].set & CPU_VPID)
		ept_vpid.val = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	write_cr0((read_cr0() & fix_cr0_clr) | fix_cr0_set);
	write_cr4((read_cr4() & fix_cr4_clr) | fix_cr4_set | X86_CR4_VMXE);

	*vmxon_region = basic.revision;

	guest_stack = alloc_page();
	memset(guest_stack, 0, PAGE_SIZE);
	guest_syscall_stack = alloc_page();
	memset(guest_syscall_stack, 0, PAGE_SIZE);
}

static int test_vmx_capability(void)
{
	struct cpuid r;
	u64 ret1, ret2;
	u64 ia32_feature_control;
	r = cpuid(1);
	ret1 = ((r.c) >> 5) & 1;
	ia32_feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	ret2 = ((ia32_feature_control & 0x5) == 0x5);
	if ((!ret2) && ((ia32_feature_control & 0x1) == 0)) {
		wrmsr(MSR_IA32_FEATURE_CONTROL, 0x5);
		ia32_feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
		ret2 = ((ia32_feature_control & 0x5) == 0x5);
	}
	report("test vmx capability", ret1 & ret2);
	return !(ret1 & ret2);
}

static int test_vmxon(void)
{
	int ret;
	u64 rflags;

	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	ret = vmx_on();
	report("test vmxon", !ret);
	return ret;
}

static void test_vmptrld(void)
{
	u64 rflags;
	struct vmcs *vmcs;

	vmcs = alloc_page();
	vmcs->revision_id = basic.revision;
	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	report("test vmptrld", make_vmcs_current(vmcs) == 0);
}

static void test_vmptrst(void)
{
	u64 rflags;
	int ret;
	struct vmcs *vmcs1, *vmcs2;

	vmcs1 = alloc_page();
	memset(vmcs1, 0, PAGE_SIZE);
	init_vmcs(&vmcs1);
	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	ret = vmcs_save(&vmcs2);
	report("test vmptrst", (!ret) && (vmcs1 == vmcs2));
}

/* This function can only be called in guest */
static void __attribute__((__used__)) hypercall(u32 hypercall_no)
{
	u64 val = 0;
	val = (hypercall_no & HYPERCALL_MASK) | HYPERCALL_BIT;
	hypercall_field = val;
	asm volatile("vmcall\n\t");
}

static bool is_hypercall()
{
	ulong reason, hyper_bit;

	reason = vmcs_read(EXI_REASON) & 0xff;
	hyper_bit = hypercall_field & HYPERCALL_BIT;
	if (reason == VMX_VMCALL && hyper_bit)
		return true;
	return false;
}

static int handle_hypercall()
{
	ulong hypercall_no;

	hypercall_no = hypercall_field & HYPERCALL_MASK;
	hypercall_field = 0;
	switch (hypercall_no) {
	case HYPERCALL_VMEXIT:
		return VMX_TEST_VMEXIT;
	default:
		printf("ERROR : Invalid hypercall number : %d\n", hypercall_no);
	}
	return VMX_TEST_EXIT;
}

static int exit_handler()
{
	int ret;

	current->exits++;
	current->guest_regs = regs;
	if (is_hypercall())
		ret = handle_hypercall();
	else
		ret = current->exit_handler();
	regs = current->guest_regs;
	switch (ret) {
	case VMX_TEST_VMEXIT:
	case VMX_TEST_RESUME:
		return ret;
	case VMX_TEST_EXIT:
		break;
	default:
		printf("ERROR : Invalid exit_handler return val %d.\n"
			, ret);
	}
	print_vmexit_info();
	exit(-1);
	return 0;
}

static int vmx_run()
{
	u32 ret = 0, fail = 0;

	while (1) {
		asm volatile (
			"mov %%rsp, %%rsi\n\t"
			"mov %2, %%rdi\n\t"
			"vmwrite %%rsi, %%rdi\n\t"

			LOAD_GPR_C
			"cmpl $0, %1\n\t"
			"jne 1f\n\t"
			LOAD_RFLAGS
			"vmlaunch\n\t"
			"jmp 2f\n\t"
			"1: "
			"vmresume\n\t"
			"2: "
			"setbe %0\n\t"
			"vmx_return:\n\t"
			SAVE_GPR_C
			SAVE_RFLAGS
			: "=m"(fail)
			: "m"(launched), "i"(HOST_RSP)
			: "rdi", "rsi", "memory", "cc"

		);
		if (fail)
			ret = launched ? VMX_TEST_RESUME_ERR :
				VMX_TEST_LAUNCH_ERR;
		else {
			launched = 1;
			ret = exit_handler();
		}
		if (ret != VMX_TEST_RESUME)
			break;
	}
	launched = 0;
	switch (ret) {
	case VMX_TEST_VMEXIT:
		return 0;
	case VMX_TEST_LAUNCH_ERR:
		printf("%s : vmlaunch failed.\n", __func__);
		if ((!(regs.rflags & X86_EFLAGS_CF) && !(regs.rflags & X86_EFLAGS_ZF))
			|| ((regs.rflags & X86_EFLAGS_CF) && (regs.rflags & X86_EFLAGS_ZF)))
			printf("\tvmlaunch set wrong flags\n");
		report("test vmlaunch", 0);
		break;
	case VMX_TEST_RESUME_ERR:
		printf("%s : vmresume failed.\n", __func__);
		if ((!(regs.rflags & X86_EFLAGS_CF) && !(regs.rflags & X86_EFLAGS_ZF))
			|| ((regs.rflags & X86_EFLAGS_CF) && (regs.rflags & X86_EFLAGS_ZF)))
			printf("\tvmresume set wrong flags\n");
		report("test vmresume", 0);
		break;
	default:
		printf("%s : unhandled ret from exit_handler, ret=%d.\n", __func__, ret);
		break;
	}
	return 1;
}

static int test_run(struct vmx_test *test)
{
	if (test->name == NULL)
		test->name = "(no name)";
	if (vmx_on()) {
		printf("%s : vmxon failed.\n", __func__);
		return 1;
	}
	init_vmcs(&(test->vmcs));
	/* Directly call test->init is ok here, init_vmcs has done
	   vmcs init, vmclear and vmptrld*/
	if (test->init)
		test->init(test->vmcs);
	test->exits = 0;
	current = test;
	regs = test->guest_regs;
	vmcs_write(GUEST_RFLAGS, regs.rflags | 0x2);
	launched = 0;
	printf("\nTest suite : %s\n", test->name);
	vmx_run();
	if (vmx_off()) {
		printf("%s : vmxoff failed.\n", __func__);
		return 1;
	}
	return 0;
}

static void basic_init()
{
}

static void basic_guest_main()
{
	/* Here is null guest_main, print Hello World */
	printf("\tHello World, this is null_guest_main!\n");
}

static int basic_exit_handler()
{
	u64 guest_rip;
	ulong reason;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;

	switch (reason) {
	case VMX_VMCALL:
		print_vmexit_info();
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		break;
	}
	printf("ERROR : Unhandled vmx exit.\n");
	print_vmexit_info();
	return VMX_TEST_EXIT;
}

static void basic_syscall_handler(u64 syscall_no)
{
}

static void vmenter_main()
{
	u64 rax;
	u64 rsp, resume_rsp;

	report("test vmlaunch", 1);

	asm volatile(
		"mov %%rsp, %0\n\t"
		"mov %3, %%rax\n\t"
		"vmcall\n\t"
		"mov %%rax, %1\n\t"
		"mov %%rsp, %2\n\t"
		: "=r"(rsp), "=r"(rax), "=r"(resume_rsp)
		: "g"(0xABCD));
	report("test vmresume", (rax == 0xFFFF) && (rsp == resume_rsp));
}

static int vmenter_exit_handler()
{
	u64 guest_rip;
	ulong reason;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		if (current->guest_regs.rax != 0xABCD) {
			report("test vmresume", 0);
			return VMX_TEST_VMEXIT;
		}
		current->guest_regs.rax = 0xFFFF;
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		report("test vmresume", 0);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}


/* name/init/guest_main/exit_handler/syscall_handler/guest_regs
   basic_* just implement some basic functions */
static struct vmx_test vmx_tests[] = {
	{ "null", basic_init, basic_guest_main, basic_exit_handler,
		basic_syscall_handler, {0} },
	{ "vmenter", basic_init, vmenter_main, vmenter_exit_handler,
		basic_syscall_handler, {0} },
};

int main(void)
{
	int i;

	setup_vm();
	setup_idt();

	if (test_vmx_capability() != 0) {
		printf("ERROR : vmx not supported, check +vmx option\n");
		goto exit;
	}
	init_vmx();
	/* Set basic test ctxt the same as "null" */
	current = &vmx_tests[0];
	if (test_vmxon() != 0)
		goto exit;
	test_vmptrld();
	test_vmclear();
	test_vmptrst();
	init_vmcs(&vmcs_root);
	if (vmx_run()) {
		report("test vmlaunch", 0);
		goto exit;
	}
	test_vmxoff();

	for (i = 1; i < ARRAY_SIZE(vmx_tests); ++i) {
		if (test_run(&vmx_tests[i]))
			goto exit;
	}

exit:
	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}
