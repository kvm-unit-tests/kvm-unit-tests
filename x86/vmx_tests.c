#include "vmx.h"
#include "msr.h"
#include "processor.h"
#include "vm.h"

u64 ia32_pat;
u64 ia32_efer;
volatile u32 stage;

static inline void vmcall()
{
	asm volatile("vmcall");
}

static inline void set_stage(u32 s)
{
	barrier();
	stage = s;
	barrier();
}

void basic_init()
{
}

void basic_guest_main()
{
	/* Here is a basic guest_main, print Hello World */
	printf("\tHello World, this is null_guest_main!\n");
}

int basic_exit_handler()
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

void basic_syscall_handler(u64 syscall_no)
{
}

void vmenter_main()
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

int vmenter_exit_handler()
{
	u64 guest_rip;
	ulong reason;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		if (regs.rax != 0xABCD) {
			report("test vmresume", 0);
			return VMX_TEST_VMEXIT;
		}
		regs.rax = 0xFFFF;
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		report("test vmresume", 0);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

void msr_bmp_init()
{
	void *msr_bitmap;
	u32 ctrl_cpu0;

	msr_bitmap = alloc_page();
	memset(msr_bitmap, 0x0, PAGE_SIZE);
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_MSR_BITMAP;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(MSR_BITMAP, (u64)msr_bitmap);
}

static void test_ctrl_pat_init()
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	ctrl_ent = vmcs_read(ENT_CONTROLS);
	ctrl_exi = vmcs_read(EXI_CONTROLS);
	vmcs_write(ENT_CONTROLS, ctrl_ent | ENT_LOAD_PAT);
	vmcs_write(EXI_CONTROLS, ctrl_exi | (EXI_SAVE_PAT | EXI_LOAD_PAT));
	ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	vmcs_write(GUEST_PAT, 0x0);
	vmcs_write(HOST_PAT, ia32_pat);
}

static void test_ctrl_pat_main()
{
	u64 guest_ia32_pat;

	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_PAT))
		printf("\tENT_LOAD_PAT is not supported.\n");
	else {
		if (guest_ia32_pat != 0) {
			report("Entry load PAT", 0);
			return;
		}
	}
	wrmsr(MSR_IA32_CR_PAT, 0x6);
	vmcall();
	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (ctrl_enter_rev.clr & ENT_LOAD_PAT) {
		if (guest_ia32_pat != ia32_pat) {
			report("Entry load PAT", 0);
			return;
		}
		report("Entry load PAT", 1);
	}
}

static int test_ctrl_pat_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u64 guest_pat;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		guest_pat = vmcs_read(GUEST_PAT);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_PAT)) {
			printf("\tEXI_SAVE_PAT is not supported\n");
			vmcs_write(GUEST_PAT, 0x6);
		} else {
			if (guest_pat == 0x6)
				report("Exit save PAT", 1);
			else
				report("Exit save PAT", 0);
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_PAT))
			printf("\tEXI_LOAD_PAT is not supported\n");
		else {
			if (rdmsr(MSR_IA32_CR_PAT) == ia32_pat)
				report("Exit load PAT", 1);
			else
				report("Exit load PAT", 0);
		}
		vmcs_write(GUEST_PAT, ia32_pat);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Undefined exit reason, reason = %d.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

static void test_ctrl_efer_init()
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	ctrl_ent = vmcs_read(ENT_CONTROLS) | ENT_LOAD_EFER;
	ctrl_exi = vmcs_read(EXI_CONTROLS) | EXI_SAVE_EFER | EXI_LOAD_EFER;
	vmcs_write(ENT_CONTROLS, ctrl_ent & ctrl_enter_rev.clr);
	vmcs_write(EXI_CONTROLS, ctrl_exi & ctrl_exit_rev.clr);
	ia32_efer = rdmsr(MSR_EFER);
	vmcs_write(GUEST_EFER, ia32_efer ^ EFER_NX);
	vmcs_write(HOST_EFER, ia32_efer ^ EFER_NX);
}

static void test_ctrl_efer_main()
{
	u64 guest_ia32_efer;

	guest_ia32_efer = rdmsr(MSR_EFER);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_EFER))
		printf("\tENT_LOAD_EFER is not supported.\n");
	else {
		if (guest_ia32_efer != (ia32_efer ^ EFER_NX)) {
			report("Entry load EFER", 0);
			return;
		}
	}
	wrmsr(MSR_EFER, ia32_efer);
	vmcall();
	guest_ia32_efer = rdmsr(MSR_EFER);
	if (ctrl_enter_rev.clr & ENT_LOAD_EFER) {
		if (guest_ia32_efer != ia32_efer) {
			report("Entry load EFER", 0);
			return;
		}
		report("Entry load EFER", 1);
	}
}

static int test_ctrl_efer_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u64 guest_efer;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		guest_efer = vmcs_read(GUEST_EFER);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_EFER)) {
			printf("\tEXI_SAVE_EFER is not supported\n");
			vmcs_write(GUEST_EFER, ia32_efer);
		} else {
			if (guest_efer == ia32_efer)
				report("Exit save EFER", 1);
			else
				report("Exit save EFER", 0);
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_EFER)) {
			printf("\tEXI_LOAD_EFER is not supported\n");
			wrmsr(MSR_EFER, ia32_efer ^ EFER_NX);
		} else {
			if (rdmsr(MSR_EFER) == (ia32_efer ^ EFER_NX))
				report("Exit load EFER", 1);
			else
				report("Exit load EFER", 0);
		}
		vmcs_write(GUEST_PAT, ia32_efer);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Undefined exit reason, reason = %d.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

u32 guest_cr0, guest_cr4;

static void cr_shadowing_main()
{
	u32 cr0, cr4, tmp;

	// Test read through
	set_stage(0);
	guest_cr0 = read_cr0();
	if (stage == 1)
		report("Read through CR0", 0);
	else
		vmcall();
	set_stage(1);
	guest_cr4 = read_cr4();
	if (stage == 2)
		report("Read through CR4", 0);
	else
		vmcall();
	// Test write through
	guest_cr0 = guest_cr0 ^ (X86_CR0_TS | X86_CR0_MP);
	guest_cr4 = guest_cr4 ^ (X86_CR4_TSD | X86_CR4_DE);
	set_stage(2);
	write_cr0(guest_cr0);
	if (stage == 3)
		report("Write throuth CR0", 0);
	else
		vmcall();
	set_stage(3);
	write_cr4(guest_cr4);
	if (stage == 4)
		report("Write through CR4", 0);
	else
		vmcall();
	// Test read shadow
	set_stage(4);
	vmcall();
	cr0 = read_cr0();
	if (stage != 5) {
		if (cr0 == guest_cr0)
			report("Read shadowing CR0", 1);
		else
			report("Read shadowing CR0", 0);
	}
	set_stage(5);
	cr4 = read_cr4();
	if (stage != 6) {
		if (cr4 == guest_cr4)
			report("Read shadowing CR4", 1);
		else
			report("Read shadowing CR4", 0);
	}
	// Test write shadow (same value with shadow)
	set_stage(6);
	write_cr0(guest_cr0);
	if (stage == 7)
		report("Write shadowing CR0 (same value with shadow)", 0);
	else
		vmcall();
	set_stage(7);
	write_cr4(guest_cr4);
	if (stage == 8)
		report("Write shadowing CR4 (same value with shadow)", 0);
	else
		vmcall();
	// Test write shadow (different value)
	set_stage(8);
	tmp = guest_cr0 ^ X86_CR0_TS;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 9)
		report("Write shadowing different X86_CR0_TS", 0);
	else
		report("Write shadowing different X86_CR0_TS", 1);
	set_stage(9);
	tmp = guest_cr0 ^ X86_CR0_MP;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 10)
		report("Write shadowing different X86_CR0_MP", 0);
	else
		report("Write shadowing different X86_CR0_MP", 1);
	set_stage(10);
	tmp = guest_cr4 ^ X86_CR4_TSD;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 11)
		report("Write shadowing different X86_CR4_TSD", 0);
	else
		report("Write shadowing different X86_CR4_TSD", 1);
	set_stage(11);
	tmp = guest_cr4 ^ X86_CR4_DE;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 12)
		report("Write shadowing different X86_CR4_DE", 0);
	else
		report("Write shadowing different X86_CR4_DE", 1);
}

static int cr_shadowing_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	u32 exit_qual;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	switch (reason) {
	case VMX_VMCALL:
		switch (stage) {
		case 0:
			if (guest_cr0 == vmcs_read(GUEST_CR0))
				report("Read through CR0", 1);
			else
				report("Read through CR0", 0);
			break;
		case 1:
			if (guest_cr4 == vmcs_read(GUEST_CR4))
				report("Read through CR4", 1);
			else
				report("Read through CR4", 0);
			break;
		case 2:
			if (guest_cr0 == vmcs_read(GUEST_CR0))
				report("Write through CR0", 1);
			else
				report("Write through CR0", 0);
			break;
		case 3:
			if (guest_cr4 == vmcs_read(GUEST_CR4))
				report("Write through CR4", 1);
			else
				report("Write through CR4", 0);
			break;
		case 4:
			guest_cr0 = vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP);
			guest_cr4 = vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE);
			vmcs_write(CR0_MASK, X86_CR0_TS | X86_CR0_MP);
			vmcs_write(CR0_READ_SHADOW, guest_cr0 & (X86_CR0_TS | X86_CR0_MP));
			vmcs_write(CR4_MASK, X86_CR4_TSD | X86_CR4_DE);
			vmcs_write(CR4_READ_SHADOW, guest_cr4 & (X86_CR4_TSD | X86_CR4_DE));
			break;
		case 6:
			if (guest_cr0 == (vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP)))
				report("Write shadowing CR0 (same value)", 1);
			else
				report("Write shadowing CR0 (same value)", 0);
			break;
		case 7:
			if (guest_cr4 == (vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE)))
				report("Write shadowing CR4 (same value)", 1);
			else
				report("Write shadowing CR4 (same value)", 0);
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_CR:
		switch (stage) {
		case 4:
			report("Read shadowing CR0", 0);
			set_stage(stage + 1);
			break;
		case 5:
			report("Read shadowing CR4", 0);
			set_stage(stage + 1);
			break;
		case 6:
			report("Write shadowing CR0 (same value)", 0);
			set_stage(stage + 1);
			break;
		case 7:
			report("Write shadowing CR4 (same value)", 0);
			set_stage(stage + 1);
			break;
		case 8:
		case 9:
			// 0x600 encodes "mov %esi, %cr0"
			if (exit_qual == 0x600)
				set_stage(stage + 1);
			break;
		case 10:
		case 11:
			// 0x604 encodes "mov %esi, %cr4"
			if (exit_qual == 0x604)
				set_stage(stage + 1);
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		printf("Unknown exit reason, %d\n", reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

/* name/init/guest_main/exit_handler/syscall_handler/guest_regs
   basic_* just implement some basic functions */
struct vmx_test vmx_tests[] = {
	{ "null", basic_init, basic_guest_main, basic_exit_handler,
		basic_syscall_handler, {0} },
	{ "vmenter", basic_init, vmenter_main, vmenter_exit_handler,
		basic_syscall_handler, {0} },
	{ "control field PAT", test_ctrl_pat_init, test_ctrl_pat_main,
		test_ctrl_pat_exit_handler, basic_syscall_handler, {0} },
	{ "control field EFER", test_ctrl_efer_init, test_ctrl_efer_main,
		test_ctrl_efer_exit_handler, basic_syscall_handler, {0} },
	{ "CR shadowing", basic_init, cr_shadowing_main,
		cr_shadowing_exit_handler, basic_syscall_handler, {0} },
	{ NULL, NULL, NULL, NULL, NULL, {0} },
};
