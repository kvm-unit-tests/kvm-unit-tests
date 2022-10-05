/*
 * All test cases of nested virtualization should be in this file
 *
 * Author : Arthur Chunqi Li <yzt356@gmail.com>
 */

#include <asm/debugreg.h>

#include "vmx.h"
#include "msr.h"
#include "processor.h"
#include "vm.h"
#include "pci.h"
#include "fwcfg.h"
#include "isr.h"
#include "desc.h"
#include "apic.h"
#include "types.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "smp.h"
#include "delay.h"
#include "access.h"
#include "x86/usermode.h"

/*
 * vmcs.GUEST_PENDING_DEBUG has the same format as DR6, although some bits that
 * are legal in DR6 are reserved in vmcs.GUEST_PENDING_DEBUG.  And if any data
 * or I/O breakpoint matches *and* was enabled, bit 12 is also set.
 */
#define PENDING_DBG_TRAP	BIT(12)

#define VPID_CAP_INVVPID_TYPES_SHIFT 40

u64 ia32_pat;
u64 ia32_efer;
void *io_bitmap_a, *io_bitmap_b;
u16 ioport;

unsigned long *pml4;
u64 eptp;
void *data_page1, *data_page2;

phys_addr_t pci_physaddr;

void *pml_log;
#define PML_INDEX 512

static inline unsigned ffs(unsigned x)
{
	int pos = -1;

	__asm__ __volatile__("bsf %1, %%eax; cmovnz %%eax, %0"
			     : "+r"(pos) : "rm"(x) : "eax");
	return pos + 1;
}

static inline void vmcall(void)
{
	asm volatile("vmcall");
}

static void basic_guest_main(void)
{
	report_pass("Basic VMX test");
}

static int basic_exit_handler(union exit_reason exit_reason)
{
	report_fail("Basic VMX test");
	print_vmexit_info(exit_reason);
	return VMX_TEST_EXIT;
}

static void vmenter_main(void)
{
	u64 rax;
	u64 rsp, resume_rsp;

	report_pass("test vmlaunch");

	asm volatile(
		"mov %%rsp, %0\n\t"
		"mov %3, %%rax\n\t"
		"vmcall\n\t"
		"mov %%rax, %1\n\t"
		"mov %%rsp, %2\n\t"
		: "=r"(rsp), "=r"(rax), "=r"(resume_rsp)
		: "g"(0xABCD));
	report((rax == 0xFFFF) && (rsp == resume_rsp), "test vmresume");
}

static int vmenter_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip = vmcs_read(GUEST_RIP);

	switch (exit_reason.basic) {
	case VMX_VMCALL:
		if (regs.rax != 0xABCD) {
			report_fail("test vmresume");
			return VMX_TEST_VMEXIT;
		}
		regs.rax = 0xFFFF;
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		report_fail("test vmresume");
		print_vmexit_info(exit_reason);
	}
	return VMX_TEST_VMEXIT;
}

u32 preempt_scale;
volatile unsigned long long tsc_val;
volatile u32 preempt_val;
u64 saved_rip;

static int preemption_timer_init(struct vmcs *vmcs)
{
	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		printf("\tPreemption timer is not supported\n");
		return VMX_TEST_EXIT;
	}
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) | PIN_PREEMPT);
	preempt_val = 10000000;
	vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
	preempt_scale = rdmsr(MSR_IA32_VMX_MISC) & 0x1F;

	if (!(ctrl_exit_rev.clr & EXI_SAVE_PREEMPT))
		printf("\tSave preemption value is not supported\n");

	return VMX_TEST_START;
}

static void preemption_timer_main(void)
{
	tsc_val = rdtsc();
	if (ctrl_exit_rev.clr & EXI_SAVE_PREEMPT) {
		vmx_set_test_stage(0);
		vmcall();
		if (vmx_get_test_stage() == 1)
			vmcall();
	}
	vmx_set_test_stage(1);
	while (vmx_get_test_stage() == 1) {
		if (((rdtsc() - tsc_val) >> preempt_scale)
				> 10 * preempt_val) {
			vmx_set_test_stage(2);
			vmcall();
		}
	}
	tsc_val = rdtsc();
	asm volatile ("hlt");
	vmcall();
	vmx_set_test_stage(5);
	vmcall();
}

static int preemption_timer_exit_handler(union exit_reason exit_reason)
{
	bool guest_halted;
	u64 guest_rip;
	u32 insn_len;
	u32 ctrl_exit;

	guest_rip = vmcs_read(GUEST_RIP);
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (exit_reason.basic) {
	case VMX_PREEMPT:
		switch (vmx_get_test_stage()) {
		case 1:
		case 2:
			report(((rdtsc() - tsc_val) >> preempt_scale) >= preempt_val,
			       "busy-wait for preemption timer");
			vmx_set_test_stage(3);
			vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
			return VMX_TEST_RESUME;
		case 3:
			guest_halted =
				(vmcs_read(GUEST_ACTV_STATE) == ACTV_HLT);
			report(((rdtsc() - tsc_val) >> preempt_scale) >= preempt_val
			        && guest_halted,
			       "preemption timer during hlt");
			vmx_set_test_stage(4);
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) & ~PIN_PREEMPT);
			vmcs_write(EXI_CONTROLS,
				   vmcs_read(EXI_CONTROLS) & ~EXI_SAVE_PREEMPT);
			vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
			return VMX_TEST_RESUME;
		case 4:
			report(saved_rip == guest_rip,
			       "preemption timer with 0 value");
			break;
		default:
			report_fail("Invalid stage.");
			print_vmexit_info(exit_reason);
			break;
		}
		break;
	case VMX_VMCALL:
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		switch (vmx_get_test_stage()) {
		case 0:
			report(vmcs_read(PREEMPT_TIMER_VALUE) == preempt_val,
			       "Keep preemption value");
			vmx_set_test_stage(1);
			vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
			ctrl_exit = (vmcs_read(EXI_CONTROLS) |
				EXI_SAVE_PREEMPT) & ctrl_exit_rev.clr;
			vmcs_write(EXI_CONTROLS, ctrl_exit);
			return VMX_TEST_RESUME;
		case 1:
			report(vmcs_read(PREEMPT_TIMER_VALUE) < preempt_val,
			       "Save preemption value");
			return VMX_TEST_RESUME;
		case 2:
			report_fail("busy-wait for preemption timer");
			vmx_set_test_stage(3);
			vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
			return VMX_TEST_RESUME;
		case 3:
			report_fail("preemption timer during hlt");
			vmx_set_test_stage(4);
			/* fall through */
		case 4:
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) | PIN_PREEMPT);
			vmcs_write(PREEMPT_TIMER_VALUE, 0);
			saved_rip = guest_rip + insn_len;
			return VMX_TEST_RESUME;
		case 5:
			report_fail("preemption timer with 0 value (vmcall stage 5)");
			break;
		default:
			// Should not reach here
			report_fail("unexpected stage, %d",
				    vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		break;
	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_PREEMPT);
	return VMX_TEST_VMEXIT;
}

static void msr_bmp_init(void)
{
	void *msr_bitmap;
	u32 ctrl_cpu0;

	msr_bitmap = alloc_page();
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_MSR_BITMAP;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(MSR_BITMAP, (u64)msr_bitmap);
}

static void *get_msr_bitmap(void)
{
	void *msr_bitmap;

	if (vmcs_read(CPU_EXEC_CTRL0) & CPU_MSR_BITMAP) {
		msr_bitmap = (void *)vmcs_read(MSR_BITMAP);
	} else {
		msr_bitmap = alloc_page();
		memset(msr_bitmap, 0xff, PAGE_SIZE);
		vmcs_write(MSR_BITMAP, (u64)msr_bitmap);
		vmcs_set_bits(CPU_EXEC_CTRL0, CPU_MSR_BITMAP);
	}

	return msr_bitmap;
}

static void disable_intercept_for_x2apic_msrs(void)
{
	unsigned long *msr_bitmap = (unsigned long *)get_msr_bitmap();
	u32 msr;

	for (msr = APIC_BASE_MSR;
		 msr < (APIC_BASE_MSR+0xff);
		 msr += BITS_PER_LONG) {
		unsigned int word = msr / BITS_PER_LONG;

		msr_bitmap[word] = 0;
		msr_bitmap[word + (0x800 / sizeof(long))] = 0;
	}
}

static int test_ctrl_pat_init(struct vmcs *vmcs)
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	if (!(ctrl_exit_rev.clr & EXI_SAVE_PAT) &&
	    !(ctrl_exit_rev.clr & EXI_LOAD_PAT) &&
	    !(ctrl_enter_rev.clr & ENT_LOAD_PAT)) {
		printf("\tSave/load PAT is not supported\n");
		return 1;
	}

	ctrl_ent = vmcs_read(ENT_CONTROLS);
	ctrl_exi = vmcs_read(EXI_CONTROLS);
	ctrl_ent |= ctrl_enter_rev.clr & ENT_LOAD_PAT;
	ctrl_exi |= ctrl_exit_rev.clr & (EXI_SAVE_PAT | EXI_LOAD_PAT);
	vmcs_write(ENT_CONTROLS, ctrl_ent);
	vmcs_write(EXI_CONTROLS, ctrl_exi);
	ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	vmcs_write(GUEST_PAT, 0x0);
	vmcs_write(HOST_PAT, ia32_pat);
	return VMX_TEST_START;
}

static void test_ctrl_pat_main(void)
{
	u64 guest_ia32_pat;

	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_PAT))
		printf("\tENT_LOAD_PAT is not supported.\n");
	else {
		if (guest_ia32_pat != 0) {
			report_fail("Entry load PAT");
			return;
		}
	}
	wrmsr(MSR_IA32_CR_PAT, 0x6);
	vmcall();
	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (ctrl_enter_rev.clr & ENT_LOAD_PAT)
		report(guest_ia32_pat == ia32_pat, "Entry load PAT");
}

static int test_ctrl_pat_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip;
	u64 guest_pat;

	guest_rip = vmcs_read(GUEST_RIP);
	switch (exit_reason.basic) {
	case VMX_VMCALL:
		guest_pat = vmcs_read(GUEST_PAT);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_PAT)) {
			printf("\tEXI_SAVE_PAT is not supported\n");
			vmcs_write(GUEST_PAT, 0x6);
		} else {
			report(guest_pat == 0x6, "Exit save PAT");
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_PAT))
			printf("\tEXI_LOAD_PAT is not supported\n");
		else
			report(rdmsr(MSR_IA32_CR_PAT) == ia32_pat,
			       "Exit load PAT");
		vmcs_write(GUEST_PAT, ia32_pat);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Unknown exit reason, 0x%x.\n", exit_reason.full);
		break;
	}
	return VMX_TEST_VMEXIT;
}

static int test_ctrl_efer_init(struct vmcs *vmcs)
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
	return VMX_TEST_START;
}

static void test_ctrl_efer_main(void)
{
	u64 guest_ia32_efer;

	guest_ia32_efer = rdmsr(MSR_EFER);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_EFER))
		printf("\tENT_LOAD_EFER is not supported.\n");
	else {
		if (guest_ia32_efer != (ia32_efer ^ EFER_NX)) {
			report_fail("Entry load EFER");
			return;
		}
	}
	wrmsr(MSR_EFER, ia32_efer);
	vmcall();
	guest_ia32_efer = rdmsr(MSR_EFER);
	if (ctrl_enter_rev.clr & ENT_LOAD_EFER)
		report(guest_ia32_efer == ia32_efer, "Entry load EFER");
}

static int test_ctrl_efer_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip;
	u64 guest_efer;

	guest_rip = vmcs_read(GUEST_RIP);
	switch (exit_reason.basic) {
	case VMX_VMCALL:
		guest_efer = vmcs_read(GUEST_EFER);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_EFER)) {
			printf("\tEXI_SAVE_EFER is not supported\n");
			vmcs_write(GUEST_EFER, ia32_efer);
		} else {
			report(guest_efer == ia32_efer, "Exit save EFER");
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_EFER)) {
			printf("\tEXI_LOAD_EFER is not supported\n");
			wrmsr(MSR_EFER, ia32_efer ^ EFER_NX);
		} else {
			report(rdmsr(MSR_EFER) == (ia32_efer ^ EFER_NX),
			       "Exit load EFER");
		}
		vmcs_write(GUEST_PAT, ia32_efer);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Unknown exit reason, 0x%x.\n", exit_reason.full);
		break;
	}
	return VMX_TEST_VMEXIT;
}

u32 guest_cr0, guest_cr4;

static void cr_shadowing_main(void)
{
	u32 cr0, cr4, tmp;

	// Test read through
	vmx_set_test_stage(0);
	guest_cr0 = read_cr0();
	if (vmx_get_test_stage() == 1)
		report_fail("Read through CR0");
	else
		vmcall();
	vmx_set_test_stage(1);
	guest_cr4 = read_cr4();
	if (vmx_get_test_stage() == 2)
		report_fail("Read through CR4");
	else
		vmcall();
	// Test write through
	guest_cr0 = guest_cr0 ^ (X86_CR0_TS | X86_CR0_MP);
	guest_cr4 = guest_cr4 ^ (X86_CR4_TSD | X86_CR4_DE);
	vmx_set_test_stage(2);
	write_cr0(guest_cr0);
	if (vmx_get_test_stage() == 3)
		report_fail("Write through CR0");
	else
		vmcall();
	vmx_set_test_stage(3);
	write_cr4(guest_cr4);
	if (vmx_get_test_stage() == 4)
		report_fail("Write through CR4");
	else
		vmcall();
	// Test read shadow
	vmx_set_test_stage(4);
	vmcall();
	cr0 = read_cr0();
	if (vmx_get_test_stage() != 5)
		report(cr0 == guest_cr0, "Read shadowing CR0");
	vmx_set_test_stage(5);
	cr4 = read_cr4();
	if (vmx_get_test_stage() != 6)
		report(cr4 == guest_cr4, "Read shadowing CR4");
	// Test write shadow (same value with shadow)
	vmx_set_test_stage(6);
	write_cr0(guest_cr0);
	if (vmx_get_test_stage() == 7)
		report_fail("Write shadowing CR0 (same value with shadow)");
	else
		vmcall();
	vmx_set_test_stage(7);
	write_cr4(guest_cr4);
	if (vmx_get_test_stage() == 8)
		report_fail("Write shadowing CR4 (same value with shadow)");
	else
		vmcall();
	// Test write shadow (different value)
	vmx_set_test_stage(8);
	tmp = guest_cr0 ^ X86_CR0_TS;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report(vmx_get_test_stage() == 9,
	       "Write shadowing different X86_CR0_TS");
	vmx_set_test_stage(9);
	tmp = guest_cr0 ^ X86_CR0_MP;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report(vmx_get_test_stage() == 10,
	       "Write shadowing different X86_CR0_MP");
	vmx_set_test_stage(10);
	tmp = guest_cr4 ^ X86_CR4_TSD;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report(vmx_get_test_stage() == 11,
	       "Write shadowing different X86_CR4_TSD");
	vmx_set_test_stage(11);
	tmp = guest_cr4 ^ X86_CR4_DE;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	report(vmx_get_test_stage() == 12,
	       "Write shadowing different X86_CR4_DE");
}

static int cr_shadowing_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip;
	u32 insn_len;
	u32 exit_qual;

	guest_rip = vmcs_read(GUEST_RIP);
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	switch (exit_reason.basic) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			report(guest_cr0 == vmcs_read(GUEST_CR0),
			       "Read through CR0");
			break;
		case 1:
			report(guest_cr4 == vmcs_read(GUEST_CR4),
			       "Read through CR4");
			break;
		case 2:
			report(guest_cr0 == vmcs_read(GUEST_CR0),
			       "Write through CR0");
			break;
		case 3:
			report(guest_cr4 == vmcs_read(GUEST_CR4),
			       "Write through CR4");
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
			report(guest_cr0 == (vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP)),
			       "Write shadowing CR0 (same value)");
			break;
		case 7:
			report(guest_cr4 == (vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE)),
			       "Write shadowing CR4 (same value)");
			break;
		default:
			// Should not reach here
			report_fail("unexpected stage, %d",
				    vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_CR:
		switch (vmx_get_test_stage()) {
		case 4:
			report_fail("Read shadowing CR0");
			vmx_inc_test_stage();
			break;
		case 5:
			report_fail("Read shadowing CR4");
			vmx_inc_test_stage();
			break;
		case 6:
			report_fail("Write shadowing CR0 (same value)");
			vmx_inc_test_stage();
			break;
		case 7:
			report_fail("Write shadowing CR4 (same value)");
			vmx_inc_test_stage();
			break;
		case 8:
		case 9:
			// 0x600 encodes "mov %esi, %cr0"
			if (exit_qual == 0x600)
				vmx_inc_test_stage();
			break;
		case 10:
		case 11:
			// 0x604 encodes "mov %esi, %cr4"
			if (exit_qual == 0x604)
				vmx_inc_test_stage();
			break;
		default:
			// Should not reach here
			report_fail("unexpected stage, %d",
				    vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}
	return VMX_TEST_VMEXIT;
}

static int iobmp_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu0;

	io_bitmap_a = alloc_page();
	io_bitmap_b = alloc_page();
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_IO_BITMAP;
	ctrl_cpu0 &= (~CPU_IO);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(IO_BITMAP_A, (u64)io_bitmap_a);
	vmcs_write(IO_BITMAP_B, (u64)io_bitmap_b);
	return VMX_TEST_START;
}

static void iobmp_main(void)
{
	// stage 0, test IO pass
	vmx_set_test_stage(0);
	inb(0x5000);
	outb(0x0, 0x5000);
	report(vmx_get_test_stage() == 0, "I/O bitmap - I/O pass");
	// test IO width, in/out
	((u8 *)io_bitmap_a)[0] = 0xFF;
	vmx_set_test_stage(2);
	inb(0x0);
	report(vmx_get_test_stage() == 3, "I/O bitmap - trap in");
	vmx_set_test_stage(3);
	outw(0x0, 0x0);
	report(vmx_get_test_stage() == 4, "I/O bitmap - trap out");
	vmx_set_test_stage(4);
	inl(0x0);
	report(vmx_get_test_stage() == 5, "I/O bitmap - I/O width, long");
	// test low/high IO port
	vmx_set_test_stage(5);
	((u8 *)io_bitmap_a)[0x5000 / 8] = (1 << (0x5000 % 8));
	inb(0x5000);
	report(vmx_get_test_stage() == 6, "I/O bitmap - I/O port, low part");
	vmx_set_test_stage(6);
	((u8 *)io_bitmap_b)[0x1000 / 8] = (1 << (0x1000 % 8));
	inb(0x9000);
	report(vmx_get_test_stage() == 7, "I/O bitmap - I/O port, high part");
	// test partial pass
	vmx_set_test_stage(7);
	inl(0x4FFF);
	report(vmx_get_test_stage() == 8, "I/O bitmap - partial pass");
	// test overrun
	vmx_set_test_stage(8);
	memset(io_bitmap_a, 0x0, PAGE_SIZE);
	memset(io_bitmap_b, 0x0, PAGE_SIZE);
	inl(0xFFFF);
	report(vmx_get_test_stage() == 9, "I/O bitmap - overrun");
	vmx_set_test_stage(9);
	vmcall();
	outb(0x0, 0x0);
	report(vmx_get_test_stage() == 9,
	       "I/O bitmap - ignore unconditional exiting");
	vmx_set_test_stage(10);
	vmcall();
	outb(0x0, 0x0);
	report(vmx_get_test_stage() == 11,
	       "I/O bitmap - unconditional exiting");
}

static int iobmp_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip;
	ulong exit_qual;
	u32 insn_len, ctrl_cpu0;

	guest_rip = vmcs_read(GUEST_RIP);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (exit_reason.basic) {
	case VMX_IO:
		switch (vmx_get_test_stage()) {
		case 0:
		case 1:
			vmx_inc_test_stage();
			break;
		case 2:
			report((exit_qual & VMX_IO_SIZE_MASK) == _VMX_IO_BYTE,
			       "I/O bitmap - I/O width, byte");
			report(exit_qual & VMX_IO_IN,
			       "I/O bitmap - I/O direction, in");
			vmx_inc_test_stage();
			break;
		case 3:
			report((exit_qual & VMX_IO_SIZE_MASK) == _VMX_IO_WORD,
			       "I/O bitmap - I/O width, word");
			report(!(exit_qual & VMX_IO_IN),
			       "I/O bitmap - I/O direction, out");
			vmx_inc_test_stage();
			break;
		case 4:
			report((exit_qual & VMX_IO_SIZE_MASK) == _VMX_IO_LONG,
			       "I/O bitmap - I/O width, long");
			vmx_inc_test_stage();
			break;
		case 5:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x5000)
				vmx_inc_test_stage();
			break;
		case 6:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x9000)
				vmx_inc_test_stage();
			break;
		case 7:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x4FFF)
				vmx_inc_test_stage();
			break;
		case 8:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0xFFFF)
				vmx_inc_test_stage();
			break;
		case 9:
		case 10:
			ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
			vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0 & ~CPU_IO);
			vmx_inc_test_stage();
			break;
		default:
			// Should not reach here
			report_fail("unexpected stage, %d",
				    vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 9:
			ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
			ctrl_cpu0 |= CPU_IO | CPU_IO_BITMAP;
			vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
			break;
		case 10:
			ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
			ctrl_cpu0 = (ctrl_cpu0 & ~CPU_IO_BITMAP) | CPU_IO;
			vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
			break;
		default:
			// Should not reach here
			report_fail("unexpected stage, %d",
				    vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		printf("guest_rip = %#lx\n", guest_rip);
		printf("\tERROR : Unknown exit reason, 0x%x\n", exit_reason.full);
		break;
	}
	return VMX_TEST_VMEXIT;
}

#define INSN_CPU0		0
#define INSN_CPU1		1
#define INSN_ALWAYS_TRAP	2

#define FIELD_EXIT_QUAL		(1 << 0)
#define FIELD_INSN_INFO		(1 << 1)

asm(
	"insn_hlt: hlt;ret\n\t"
	"insn_invlpg: invlpg 0x12345678;ret\n\t"
	"insn_mwait: xor %eax, %eax; xor %ecx, %ecx; mwait;ret\n\t"
	"insn_rdpmc: xor %ecx, %ecx; rdpmc;ret\n\t"
	"insn_rdtsc: rdtsc;ret\n\t"
	"insn_cr3_load: mov cr3,%rax; mov %rax,%cr3;ret\n\t"
	"insn_cr3_store: mov %cr3,%rax;ret\n\t"
	"insn_cr8_load: xor %eax, %eax; mov %rax,%cr8;ret\n\t"
	"insn_cr8_store: mov %cr8,%rax;ret\n\t"
	"insn_monitor: xor %eax, %eax; xor %ecx, %ecx; xor %edx, %edx; monitor;ret\n\t"
	"insn_pause: pause;ret\n\t"
	"insn_wbinvd: wbinvd;ret\n\t"
	"insn_cpuid: mov $10, %eax; cpuid;ret\n\t"
	"insn_invd: invd;ret\n\t"
	"insn_sgdt: sgdt gdt_descr;ret\n\t"
	"insn_lgdt: lgdt gdt_descr;ret\n\t"
	"insn_sidt: sidt idt_descr;ret\n\t"
	"insn_lidt: lidt idt_descr;ret\n\t"
	"insn_sldt: sldt %ax;ret\n\t"
	"insn_lldt: xor %eax, %eax; lldt %ax;ret\n\t"
	"insn_str: str %ax;ret\n\t"
	"insn_rdrand: rdrand %rax;ret\n\t"
	"insn_rdseed: rdseed %rax;ret\n\t"
);
extern void insn_hlt(void);
extern void insn_invlpg(void);
extern void insn_mwait(void);
extern void insn_rdpmc(void);
extern void insn_rdtsc(void);
extern void insn_cr3_load(void);
extern void insn_cr3_store(void);
extern void insn_cr8_load(void);
extern void insn_cr8_store(void);
extern void insn_monitor(void);
extern void insn_pause(void);
extern void insn_wbinvd(void);
extern void insn_sgdt(void);
extern void insn_lgdt(void);
extern void insn_sidt(void);
extern void insn_lidt(void);
extern void insn_sldt(void);
extern void insn_lldt(void);
extern void insn_str(void);
extern void insn_cpuid(void);
extern void insn_invd(void);
extern void insn_rdrand(void);
extern void insn_rdseed(void);

u32 cur_insn;
u64 cr3;

typedef bool (*supported_fn)(void);

static bool this_cpu_has_mwait(void)
{
	return this_cpu_has(X86_FEATURE_MWAIT);
}

struct insn_table {
	const char *name;
	u32 flag;
	void (*insn_func)(void);
	u32 type;
	u32 reason;
	ulong exit_qual;
	u32 insn_info;
	// Use FIELD_EXIT_QUAL and FIELD_INSN_INFO to define
	// which field need to be tested, reason is always tested
	u32 test_field;
	const supported_fn supported_fn;
	u8 disabled;
};

/*
 * Add more test cases of instruction intercept here. Elements in this
 * table is:
 *	name/control flag/insn function/type/exit reason/exit qulification/
 *	instruction info/field to test
 * The last field defines which fields (exit_qual and insn_info) need to be
 * tested in exit handler. If set to 0, only "reason" is checked.
 */
static struct insn_table insn_table[] = {
	// Flags for Primary Processor-Based VM-Execution Controls
	{"HLT",  CPU_HLT, insn_hlt, INSN_CPU0, 12, 0, 0, 0},
	{"INVLPG", CPU_INVLPG, insn_invlpg, INSN_CPU0, 14,
		0x12345678, 0, FIELD_EXIT_QUAL},
	{"MWAIT", CPU_MWAIT, insn_mwait, INSN_CPU0, 36, 0, 0, 0, this_cpu_has_mwait},
	{"RDPMC", CPU_RDPMC, insn_rdpmc, INSN_CPU0, 15, 0, 0, 0, this_cpu_has_pmu},
	{"RDTSC", CPU_RDTSC, insn_rdtsc, INSN_CPU0, 16, 0, 0, 0},
	{"CR3 load", CPU_CR3_LOAD, insn_cr3_load, INSN_CPU0, 28, 0x3, 0,
		FIELD_EXIT_QUAL},
	{"CR3 store", CPU_CR3_STORE, insn_cr3_store, INSN_CPU0, 28, 0x13, 0,
		FIELD_EXIT_QUAL},
	{"CR8 load", CPU_CR8_LOAD, insn_cr8_load, INSN_CPU0, 28, 0x8, 0,
		FIELD_EXIT_QUAL},
	{"CR8 store", CPU_CR8_STORE, insn_cr8_store, INSN_CPU0, 28, 0x18, 0,
		FIELD_EXIT_QUAL},
	{"MONITOR", CPU_MONITOR, insn_monitor, INSN_CPU0, 39, 0, 0, 0, this_cpu_has_mwait},
	{"PAUSE", CPU_PAUSE, insn_pause, INSN_CPU0, 40, 0, 0, 0},
	// Flags for Secondary Processor-Based VM-Execution Controls
	{"WBINVD", CPU_WBINVD, insn_wbinvd, INSN_CPU1, 54, 0, 0, 0},
	{"DESC_TABLE (SGDT)", CPU_DESC_TABLE, insn_sgdt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (LGDT)", CPU_DESC_TABLE, insn_lgdt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (SIDT)", CPU_DESC_TABLE, insn_sidt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (LIDT)", CPU_DESC_TABLE, insn_lidt, INSN_CPU1, 46, 0, 0, 0},
	{"DESC_TABLE (SLDT)", CPU_DESC_TABLE, insn_sldt, INSN_CPU1, 47, 0, 0, 0},
	{"DESC_TABLE (LLDT)", CPU_DESC_TABLE, insn_lldt, INSN_CPU1, 47, 0, 0, 0},
	{"DESC_TABLE (STR)", CPU_DESC_TABLE, insn_str, INSN_CPU1, 47, 0, 0, 0},
	/* LTR causes a #GP if done with a busy selector, so it is not tested.  */
	{"RDRAND", CPU_RDRAND, insn_rdrand, INSN_CPU1, VMX_RDRAND, 0, 0, 0},
	{"RDSEED", CPU_RDSEED, insn_rdseed, INSN_CPU1, VMX_RDSEED, 0, 0, 0},
	// Instructions always trap
	{"CPUID", 0, insn_cpuid, INSN_ALWAYS_TRAP, 10, 0, 0, 0},
	{"INVD", 0, insn_invd, INSN_ALWAYS_TRAP, 13, 0, 0, 0},
	// Instructions never trap
	{NULL},
};

static int insn_intercept_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu, cur_insn;

	ctrl_cpu = ctrl_cpu_rev[0].set | CPU_SECONDARY;
	ctrl_cpu &= ctrl_cpu_rev[0].clr;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu_rev[1].set);
	cr3 = read_cr3();

	for (cur_insn = 0; insn_table[cur_insn].name != NULL; cur_insn++) {
		if (insn_table[cur_insn].supported_fn == NULL)
			continue;
		insn_table[cur_insn].disabled = !insn_table[cur_insn].supported_fn();
	}
	return VMX_TEST_START;
}

static void insn_intercept_main(void)
{
	for (cur_insn = 0; insn_table[cur_insn].name != NULL; cur_insn++) {
		vmx_set_test_stage(cur_insn * 2);
		if ((insn_table[cur_insn].type == INSN_CPU0 &&
		     !(ctrl_cpu_rev[0].clr & insn_table[cur_insn].flag)) ||
		    (insn_table[cur_insn].type == INSN_CPU1 &&
		     !(ctrl_cpu_rev[1].clr & insn_table[cur_insn].flag))) {
			printf("\tCPU_CTRL%d.CPU_%s is not supported.\n",
			       insn_table[cur_insn].type - INSN_CPU0,
			       insn_table[cur_insn].name);
			continue;
		}

		if (insn_table[cur_insn].disabled) {
			printf("\tFeature required for %s is not supported.\n",
			       insn_table[cur_insn].name);
			continue;
		}

		if ((insn_table[cur_insn].type == INSN_CPU0 &&
		     !(ctrl_cpu_rev[0].set & insn_table[cur_insn].flag)) ||
		    (insn_table[cur_insn].type == INSN_CPU1 &&
		     !(ctrl_cpu_rev[1].set & insn_table[cur_insn].flag))) {
			/* skip hlt, it stalls the guest and is tested below */
			if (insn_table[cur_insn].insn_func != insn_hlt)
				insn_table[cur_insn].insn_func();
			report(vmx_get_test_stage() == cur_insn * 2,
					"execute %s",
					insn_table[cur_insn].name);
		} else if (insn_table[cur_insn].type != INSN_ALWAYS_TRAP)
			printf("\tCPU_CTRL%d.CPU_%s always traps.\n",
			       insn_table[cur_insn].type - INSN_CPU0,
			       insn_table[cur_insn].name);

		vmcall();

		insn_table[cur_insn].insn_func();
		report(vmx_get_test_stage() == cur_insn * 2 + 1,
				"intercept %s",
				insn_table[cur_insn].name);

		vmx_set_test_stage(cur_insn * 2 + 1);
		vmcall();
	}
}

static int insn_intercept_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip;
	ulong exit_qual;
	u32 insn_len;
	u32 insn_info;
	bool pass;

	guest_rip = vmcs_read(GUEST_RIP);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	insn_len = vmcs_read(EXI_INST_LEN);
	insn_info = vmcs_read(EXI_INST_INFO);

	if (exit_reason.basic == VMX_VMCALL) {
		u32 val = 0;

		if (insn_table[cur_insn].type == INSN_CPU0)
			val = vmcs_read(CPU_EXEC_CTRL0);
		else if (insn_table[cur_insn].type == INSN_CPU1)
			val = vmcs_read(CPU_EXEC_CTRL1);

		if (vmx_get_test_stage() & 1)
			val &= ~insn_table[cur_insn].flag;
		else
			val |= insn_table[cur_insn].flag;

		if (insn_table[cur_insn].type == INSN_CPU0)
			vmcs_write(CPU_EXEC_CTRL0, val | ctrl_cpu_rev[0].set);
		else if (insn_table[cur_insn].type == INSN_CPU1)
			vmcs_write(CPU_EXEC_CTRL1, val | ctrl_cpu_rev[1].set);
	} else {
		pass = (cur_insn * 2 == vmx_get_test_stage()) &&
			insn_table[cur_insn].reason == exit_reason.full;
		if (insn_table[cur_insn].test_field & FIELD_EXIT_QUAL &&
		    insn_table[cur_insn].exit_qual != exit_qual)
			pass = false;
		if (insn_table[cur_insn].test_field & FIELD_INSN_INFO &&
		    insn_table[cur_insn].insn_info != insn_info)
			pass = false;
		if (pass)
			vmx_inc_test_stage();
	}
	vmcs_write(GUEST_RIP, guest_rip + insn_len);
	return VMX_TEST_RESUME;
}

/**
 * __setup_ept - Setup the VMCS fields to enable Extended Page Tables (EPT)
 * @hpa:	Host physical address of the top-level, a.k.a. root, EPT table
 * @enable_ad:	Whether or not to enable Access/Dirty bits for EPT entries
 *
 * Returns 0 on success, 1 on failure.
 *
 * Note that @hpa doesn't need to point at actual memory if VM-Launch is
 * expected to fail, e.g. setup_dummy_ept() arbitrarily passes '0' to satisfy
 * the various EPTP consistency checks, but doesn't ensure backing for HPA '0'.
 */
static int __setup_ept(u64 hpa, bool enable_ad)
{
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
	    !(ctrl_cpu_rev[1].clr & CPU_EPT)) {
		printf("\tEPT is not supported\n");
		return 1;
	}
	if (!(ept_vpid.val & EPT_CAP_WB)) {
		printf("\tWB memtype for EPT walks not supported\n");
		return 1;
	}
	if (!(ept_vpid.val & EPT_CAP_PWL4)) {
		printf("\tPWL4 is not supported\n");
		return 1;
	}

	eptp = EPT_MEM_TYPE_WB;
	eptp |= (3 << EPTP_PG_WALK_LEN_SHIFT);
	eptp |= hpa;
	if (enable_ad)
		eptp |= EPTP_AD_FLAG;

	vmcs_write(EPTP, eptp);
	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0)| CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1)| CPU_EPT);

	return 0;
}

/**
 * setup_ept - Enable Extended Page Tables (EPT) and setup an identity map
 * @enable_ad:	Whether or not to enable Access/Dirty bits for EPT entries
 *
 * Returns 0 on success, 1 on failure.
 *
 * This is the "real" function for setting up EPT tables, i.e. use this for
 * tests that need to run code in the guest with EPT enabled.
 */
static int setup_ept(bool enable_ad)
{
	unsigned long end_of_memory;

	pml4 = alloc_page();

	if (__setup_ept(virt_to_phys(pml4), enable_ad))
		return 1;

	end_of_memory = fwcfg_get_u64(FW_CFG_RAM_SIZE);
	if (end_of_memory < (1ul << 32))
		end_of_memory = (1ul << 32);
	/* Cannot use large EPT pages if we need to track EPT
	 * accessed/dirty bits at 4K granularity.
	 */
	setup_ept_range(pml4, 0, end_of_memory, 0,
			!enable_ad && ept_2m_supported(),
			EPT_WA | EPT_RA | EPT_EA);
	return 0;
}

/**
 * setup_dummy_ept - Enable Extended Page Tables (EPT) with a dummy root HPA
 *
 * Setup EPT using a semi-arbitrary dummy root HPA.  This function is intended
 * for use by tests that need EPT enabled to verify dependent VMCS controls
 * but never expect to fully enter the guest, i.e. don't need setup the actual
 * EPT tables.
 */
static void setup_dummy_ept(void)
{
	if (__setup_ept(0, false))
		report_abort("EPT setup unexpectedly failed");
}

static int enable_unrestricted_guest(bool need_valid_ept)
{
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
	    !(ctrl_cpu_rev[1].clr & CPU_URG) ||
	    !(ctrl_cpu_rev[1].clr & CPU_EPT))
		return 1;

	if (need_valid_ept)
		setup_ept(false);
	else
		setup_dummy_ept();

	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | CPU_URG);

	return 0;
}

static void ept_enable_ad_bits(void)
{
	eptp |= EPTP_AD_FLAG;
	vmcs_write(EPTP, eptp);
}

static void ept_disable_ad_bits(void)
{
	eptp &= ~EPTP_AD_FLAG;
	vmcs_write(EPTP, eptp);
}

static int ept_ad_enabled(void)
{
	return eptp & EPTP_AD_FLAG;
}

static void ept_enable_ad_bits_or_skip_test(void)
{
	if (!ept_ad_bits_supported())
		test_skip("EPT AD bits not supported.");
	ept_enable_ad_bits();
}

static int apic_version;

static int ept_init_common(bool have_ad)
{
	int ret;
	struct pci_dev pcidev;

	/* INVEPT is required by the EPT violation handler. */
	if (!is_invept_type_supported(INVEPT_SINGLE))
		return VMX_TEST_EXIT;

	if (setup_ept(have_ad))
		return VMX_TEST_EXIT;

	data_page1 = alloc_page();
	data_page2 = alloc_page();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	*((u32 *)data_page2) = MAGIC_VAL_2;
	install_ept(pml4, (unsigned long)data_page1, (unsigned long)data_page2,
			EPT_RA | EPT_WA | EPT_EA);

	apic_version = apic_read(APIC_LVR);

	ret = pci_find_dev(PCI_VENDOR_ID_REDHAT, PCI_DEVICE_ID_REDHAT_TEST);
	if (ret != PCIDEVADDR_INVALID) {
		pci_dev_init(&pcidev, ret);
		pci_physaddr = pcidev.resource[PCI_TESTDEV_BAR_MEM];
	}

	return VMX_TEST_START;
}

static int ept_init(struct vmcs *vmcs)
{
	return ept_init_common(false);
}

static void ept_common(void)
{
	vmx_set_test_stage(0);
	if (*((u32 *)data_page2) != MAGIC_VAL_1 ||
			*((u32 *)data_page1) != MAGIC_VAL_1)
		report_fail("EPT basic framework - read");
	else {
		*((u32 *)data_page2) = MAGIC_VAL_3;
		vmcall();
		if (vmx_get_test_stage() == 1) {
			if (*((u32 *)data_page1) == MAGIC_VAL_3 &&
					*((u32 *)data_page2) == MAGIC_VAL_2)
				report_pass("EPT basic framework");
			else
				report_pass("EPT basic framework - remap");
		}
	}
	// Test EPT Misconfigurations
	vmx_set_test_stage(1);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	if (vmx_get_test_stage() != 2) {
		report_fail("EPT misconfigurations");
		goto t1;
	}
	vmx_set_test_stage(2);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	report(vmx_get_test_stage() == 3, "EPT misconfigurations");
t1:
	// Test EPT violation
	vmx_set_test_stage(3);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	report(vmx_get_test_stage() == 4, "EPT violation - page permission");
	// Violation caused by EPT paging structure
	vmx_set_test_stage(4);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_2;
	report(vmx_get_test_stage() == 5, "EPT violation - paging structure");

	// MMIO Read/Write
	vmx_set_test_stage(5);
	vmcall();

	*(u32 volatile *)pci_physaddr;
	report(vmx_get_test_stage() == 6, "MMIO EPT violation - read");

	*(u32 volatile *)pci_physaddr = MAGIC_VAL_1;
	report(vmx_get_test_stage() == 7, "MMIO EPT violation - write");
}

static void ept_main(void)
{
	ept_common();

	// Test EPT access to L1 MMIO
	vmx_set_test_stage(7);
	report(*((u32 *)0xfee00030UL) == apic_version, "EPT - MMIO access");

	// Test invalid operand for INVEPT
	vmcall();
	report(vmx_get_test_stage() == 8, "EPT - unsupported INVEPT");
}

static bool invept_test(int type, u64 eptp)
{
	bool ret, supported;

	supported = ept_vpid.val & (EPT_CAP_INVEPT_SINGLE >> INVEPT_SINGLE << type);
	ret = __invept(type, eptp);

	if (ret == !supported)
		return false;

	if (!supported)
		printf("WARNING: unsupported invept passed!\n");
	else
		printf("WARNING: invept failed!\n");

	return true;
}

static int pml_exit_handler(union exit_reason exit_reason)
{
	u16 index, count;
	u64 *pmlbuf = pml_log;
	u64 guest_rip = vmcs_read(GUEST_RIP);;
	u64 guest_cr3 = vmcs_read(GUEST_CR3);
	u32 insn_len = vmcs_read(EXI_INST_LEN);

	switch (exit_reason.basic) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			index = vmcs_read(GUEST_PML_INDEX);
			for (count = index + 1; count < PML_INDEX; count++) {
				if (pmlbuf[count] == (u64)data_page2) {
					vmx_inc_test_stage();
					clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page2);
					break;
				}
			}
			break;
		case 1:
			index = vmcs_read(GUEST_PML_INDEX);
			/* Keep clearing the dirty bit till a overflow */
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page2);
			break;
		default:
			report_fail("unexpected stage, %d.",
			       vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_PML_FULL:
		vmx_inc_test_stage();
		vmcs_write(GUEST_PML_INDEX, PML_INDEX - 1);
		return VMX_TEST_RESUME;
	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}
	return VMX_TEST_VMEXIT;
}

static int ept_exit_handler_common(union exit_reason exit_reason, bool have_ad)
{
	u64 guest_rip;
	u64 guest_cr3;
	u32 insn_len;
	u32 exit_qual;
	static unsigned long data_page1_pte, data_page1_pte_pte, memaddr_pte,
			     guest_pte_addr;

	guest_rip = vmcs_read(GUEST_RIP);
	guest_cr3 = vmcs_read(GUEST_CR3);
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	pteval_t *ptep;
	switch (exit_reason.basic) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			check_ept_ad(pml4, guest_cr3,
				     (unsigned long)data_page1,
				     have_ad ? EPT_ACCESS_FLAG : 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			check_ept_ad(pml4, guest_cr3,
				     (unsigned long)data_page2,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page2);
			if (have_ad)
				invept(INVEPT_SINGLE, eptp);
			if (*((u32 *)data_page1) == MAGIC_VAL_3 &&
					*((u32 *)data_page2) == MAGIC_VAL_2) {
				vmx_inc_test_stage();
				install_ept(pml4, (unsigned long)data_page2,
						(unsigned long)data_page2,
						EPT_RA | EPT_WA | EPT_EA);
			} else
				report_fail("EPT basic framework - write");
			break;
		case 1:
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1, EPT_WA);
			invept(INVEPT_SINGLE, eptp);
			break;
		case 2:
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1,
 				EPT_RA | EPT_WA | EPT_EA |
 				(2 << EPT_MEM_TYPE_SHIFT));
			invept(INVEPT_SINGLE, eptp);
			break;
		case 3:
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)data_page1,
						1, &data_page1_pte));
			set_ept_pte(pml4, (unsigned long)data_page1, 
				1, data_page1_pte & ~EPT_PRESENT);
			invept(INVEPT_SINGLE, eptp);
			break;
		case 4:
			ptep = get_pte_level((pgd_t *)guest_cr3, data_page1, /*level=*/2);
			guest_pte_addr = virt_to_phys(ptep) & PAGE_MASK;

			TEST_ASSERT(get_ept_pte(pml4, guest_pte_addr, 2, &data_page1_pte_pte));
			set_ept_pte(pml4, guest_pte_addr, 2,
				data_page1_pte_pte & ~EPT_PRESENT);
			invept(INVEPT_SINGLE, eptp);
			break;
		case 5:
			install_ept(pml4, (unsigned long)pci_physaddr,
				(unsigned long)pci_physaddr, 0);
			invept(INVEPT_SINGLE, eptp);
			break;
		case 7:
			if (!invept_test(0, eptp))
				vmx_inc_test_stage();
			break;
		// Should not reach here
		default:
			report_fail("ERROR - unexpected stage, %d.",
			       vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_EPT_MISCONFIG:
		switch (vmx_get_test_stage()) {
		case 1:
		case 2:
			vmx_inc_test_stage();
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1,
 				EPT_RA | EPT_WA | EPT_EA);
			invept(INVEPT_SINGLE, eptp);
			break;
		// Should not reach here
		default:
			report_fail("ERROR - unexpected stage, %d.",
			       vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	case VMX_EPT_VIOLATION:
		/*
		 * Exit-qualifications are masked not to account for advanced
		 * VM-exit information. Once KVM supports this feature, this
		 * masking should be removed.
		 */
		exit_qual &= ~EPT_VLT_GUEST_MASK;

		switch(vmx_get_test_stage()) {
		case 3:
			check_ept_ad(pml4, guest_cr3, (unsigned long)data_page1, 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			if (exit_qual == (EPT_VLT_WR | EPT_VLT_LADDR_VLD |
					EPT_VLT_PADDR))
				vmx_inc_test_stage();
			set_ept_pte(pml4, (unsigned long)data_page1,
				1, data_page1_pte | (EPT_PRESENT));
			invept(INVEPT_SINGLE, eptp);
			break;
		case 4:
			check_ept_ad(pml4, guest_cr3, (unsigned long)data_page1, 0,
				     have_ad ? EPT_ACCESS_FLAG | EPT_DIRTY_FLAG : 0);
			clear_ept_ad(pml4, guest_cr3, (unsigned long)data_page1);
			if (exit_qual == (EPT_VLT_RD |
					  (have_ad ? EPT_VLT_WR : 0) |
					  EPT_VLT_LADDR_VLD))
				vmx_inc_test_stage();
			set_ept_pte(pml4, guest_pte_addr, 2,
				data_page1_pte_pte | (EPT_PRESENT));
			invept(INVEPT_SINGLE, eptp);
			break;
		case 5:
			if (exit_qual & EPT_VLT_RD)
				vmx_inc_test_stage();
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)pci_physaddr,
						1, &memaddr_pte));
			set_ept_pte(pml4, memaddr_pte, 1, memaddr_pte | EPT_RA);
			invept(INVEPT_SINGLE, eptp);
			break;
		case 6:
			if (exit_qual & EPT_VLT_WR)
				vmx_inc_test_stage();
			TEST_ASSERT(get_ept_pte(pml4, (unsigned long)pci_physaddr,
						1, &memaddr_pte));
			set_ept_pte(pml4, memaddr_pte, 1, memaddr_pte | EPT_RA | EPT_WA);
			invept(INVEPT_SINGLE, eptp);
			break;
		default:
			// Should not reach here
			report_fail("ERROR : unexpected stage, %d",
			       vmx_get_test_stage());
			print_vmexit_info(exit_reason);
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}
	return VMX_TEST_VMEXIT;
}

static int ept_exit_handler(union exit_reason exit_reason)
{
	return ept_exit_handler_common(exit_reason, false);
}

static int eptad_init(struct vmcs *vmcs)
{
	int r = ept_init_common(true);

	if (r == VMX_TEST_EXIT)
		return r;

	if (!ept_ad_bits_supported()) {
		printf("\tEPT A/D bits are not supported");
		return VMX_TEST_EXIT;
	}

	return r;
}

static int pml_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu;
	int r = eptad_init(vmcs);

	if (r == VMX_TEST_EXIT)
		return r;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
		!(ctrl_cpu_rev[1].clr & CPU_PML)) {
		printf("\tPML is not supported");
		return VMX_TEST_EXIT;
	}

	pml_log = alloc_page();
	vmcs_write(PMLADDR, (u64)pml_log);
	vmcs_write(GUEST_PML_INDEX, PML_INDEX - 1);

	ctrl_cpu = vmcs_read(CPU_EXEC_CTRL1) | CPU_PML;
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu);

	return VMX_TEST_START;
}

static void pml_main(void)
{
	int count = 0;

	vmx_set_test_stage(0);
	*((u32 *)data_page2) = 0x1;
	vmcall();
	report(vmx_get_test_stage() == 1, "PML - Dirty GPA Logging");

	while (vmx_get_test_stage() == 1) {
		vmcall();
		*((u32 *)data_page2) = 0x1;
		if (count++ > PML_INDEX)
			break;
	}
	report(vmx_get_test_stage() == 2, "PML Full Event");
}

static void eptad_main(void)
{
	ept_common();
}

static int eptad_exit_handler(union exit_reason exit_reason)
{
	return ept_exit_handler_common(exit_reason, true);
}

#define TIMER_VECTOR	222

static volatile bool timer_fired;

static void timer_isr(isr_regs_t *regs)
{
	timer_fired = true;
	apic_write(APIC_EOI, 0);
}

static int interrupt_init(struct vmcs *vmcs)
{
	msr_bmp_init();
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);
	handle_irq(TIMER_VECTOR, timer_isr);
	return VMX_TEST_START;
}

static void interrupt_main(void)
{
	long long start, loops;

	vmx_set_test_stage(0);

	apic_write(APIC_LVTT, TIMER_VECTOR);
	irq_enable();

	apic_write(APIC_TMICT, 1);
	for (loops = 0; loops < 10000000 && !timer_fired; loops++)
		asm volatile ("nop");
	report(timer_fired, "direct interrupt while running guest");

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	apic_write(APIC_TMICT, 1);
	for (loops = 0; loops < 10000000 && !timer_fired; loops++)
		asm volatile ("nop");
	report(timer_fired, "intercepted interrupt while running guest");

	irq_enable();
	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	safe_halt();

	report(rdtsc() - start > 1000000 && timer_fired,
	       "direct interrupt + hlt");

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	safe_halt();

	report(rdtsc() - start > 10000 && timer_fired,
	       "intercepted interrupt + hlt");

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	irq_enable();
	asm volatile ("nop");
	vmcall();

	report(rdtsc() - start > 10000 && timer_fired,
	       "direct interrupt + activity state hlt");

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmcall();
	timer_fired = false;
	start = rdtsc();
	apic_write(APIC_TMICT, 1000000);

	irq_enable();
	asm volatile ("nop");
	vmcall();

	report(rdtsc() - start > 10000 && timer_fired,
	       "intercepted interrupt + activity state hlt");

	apic_write(APIC_TMICT, 0);
	irq_disable();
	vmx_set_test_stage(7);
	vmcall();
	timer_fired = false;
	apic_write(APIC_TMICT, 1);
	for (loops = 0; loops < 10000000 && !timer_fired; loops++)
		asm volatile ("nop");
	report(timer_fired,
	       "running a guest with interrupt acknowledgement set");

	apic_write(APIC_TMICT, 0);
	irq_enable();
	timer_fired = false;
	vmcall();
	report(timer_fired, "Inject an event to a halted guest");
}

static int interrupt_exit_handler(union exit_reason exit_reason)
{
	u64 guest_rip = vmcs_read(GUEST_RIP);
	u32 insn_len = vmcs_read(EXI_INST_LEN);

	switch (exit_reason.basic) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
		case 2:
		case 5:
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) | PIN_EXTINT);
			break;
		case 7:
			vmcs_write(EXI_CONTROLS, vmcs_read(EXI_CONTROLS) | EXI_INTA);
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) | PIN_EXTINT);
			break;
		case 1:
		case 3:
			vmcs_write(PIN_CONTROLS,
				   vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);
			break;
		case 4:
		case 6:
			vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
			break;

		case 8:
			vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
			vmcs_write(ENT_INTR_INFO,
				   TIMER_VECTOR |
				   (VMX_INTR_TYPE_EXT_INTR << INTR_INFO_INTR_TYPE_SHIFT) |
				   INTR_INFO_VALID_MASK);
			break;
		}
		vmx_inc_test_stage();
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_EXTINT:
		if (vmcs_read(EXI_CONTROLS) & EXI_INTA) {
			int vector = vmcs_read(EXI_INTR_INFO) & 0xff;
			handle_external_interrupt(vector);
		} else {
			irq_enable();
			asm volatile ("nop");
			irq_disable();
		}
		if (vmx_get_test_stage() >= 2)
			vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
		return VMX_TEST_RESUME;
	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}

	return VMX_TEST_VMEXIT;
}


static volatile int nmi_fired;

#define NMI_DELAY 100000000ULL

static void nmi_isr(isr_regs_t *regs)
{
	nmi_fired = true;
}

static int nmi_hlt_init(struct vmcs *vmcs)
{
	msr_bmp_init();
	handle_irq(NMI_VECTOR, nmi_isr);
	vmcs_write(PIN_CONTROLS,
		   vmcs_read(PIN_CONTROLS) & ~PIN_NMI);
	vmcs_write(PIN_CONTROLS,
		   vmcs_read(PIN_CONTROLS) & ~PIN_VIRT_NMI);
	return VMX_TEST_START;
}

static void nmi_message_thread(void *data)
{
    while (vmx_get_test_stage() != 1)
        pause();

    delay(NMI_DELAY);
    apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, id_map[0]);

    while (vmx_get_test_stage() != 2)
        pause();

    delay(NMI_DELAY);
    apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, id_map[0]);
}

static void nmi_hlt_main(void)
{
    long long start;

    if (cpu_count() < 2) {
        report_skip("%s : CPU count < 2", __func__);
        vmx_set_test_stage(-1);
        return;
    }

    vmx_set_test_stage(0);
    on_cpu_async(1, nmi_message_thread, NULL);
    start = rdtsc();
    vmx_set_test_stage(1);
    asm volatile ("hlt");
    report((rdtsc() - start > NMI_DELAY) && nmi_fired,
            "direct NMI + hlt");
    if (!nmi_fired)
        vmx_set_test_stage(-1);
    nmi_fired = false;

    vmcall();

    start = rdtsc();
    vmx_set_test_stage(2);
    asm volatile ("hlt");
    report((rdtsc() - start > NMI_DELAY) && !nmi_fired,
            "intercepted NMI + hlt");
    if (nmi_fired) {
        report(!nmi_fired, "intercepted NMI was dispatched");
        vmx_set_test_stage(-1);
        return;
    }
    vmx_set_test_stage(3);
}

static int nmi_hlt_exit_handler(union exit_reason exit_reason)
{
    u64 guest_rip = vmcs_read(GUEST_RIP);
    u32 insn_len = vmcs_read(EXI_INST_LEN);

    switch (vmx_get_test_stage()) {
    case 1:
        if (exit_reason.basic != VMX_VMCALL) {
            report_fail("VMEXIT not due to vmcall. Exit reason 0x%x",
                        exit_reason.full);
            print_vmexit_info(exit_reason);
            return VMX_TEST_VMEXIT;
        }

        vmcs_write(PIN_CONTROLS,
               vmcs_read(PIN_CONTROLS) | PIN_NMI);
        vmcs_write(PIN_CONTROLS,
               vmcs_read(PIN_CONTROLS) | PIN_VIRT_NMI);
        vmcs_write(GUEST_RIP, guest_rip + insn_len);
        break;

    case 2:
        if (exit_reason.basic != VMX_EXC_NMI) {
            report_fail("VMEXIT not due to NMI intercept. Exit reason 0x%x",
                        exit_reason.full);
            print_vmexit_info(exit_reason);
            return VMX_TEST_VMEXIT;
        }
        report_pass("NMI intercept while running guest");
        vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
        break;

    case 3:
        break;

    default:
        return VMX_TEST_VMEXIT;
    }

    if (vmx_get_test_stage() == 3)
        return VMX_TEST_VMEXIT;

    return VMX_TEST_RESUME;
}


static int dbgctls_init(struct vmcs *vmcs)
{
	u64 dr7 = 0x402;
	u64 zero = 0;

	msr_bmp_init();
	asm volatile(
		"mov %0,%%dr0\n\t"
		"mov %0,%%dr1\n\t"
		"mov %0,%%dr2\n\t"
		"mov %1,%%dr7\n\t"
		: : "r" (zero), "r" (dr7));
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0x1);
	vmcs_write(GUEST_DR7, 0x404);
	vmcs_write(GUEST_DEBUGCTL, 0x2);

	vmcs_write(ENT_CONTROLS, vmcs_read(ENT_CONTROLS) | ENT_LOAD_DBGCTLS);
	vmcs_write(EXI_CONTROLS, vmcs_read(EXI_CONTROLS) | EXI_SAVE_DBGCTLS);

	return VMX_TEST_START;
}

static void dbgctls_main(void)
{
	u64 dr7, debugctl;

	asm volatile("mov %%dr7,%0" : "=r" (dr7));
	debugctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
	/* Commented out: KVM does not support DEBUGCTL so far */
	(void)debugctl;
	report(dr7 == 0x404, "Load debug controls" /* && debugctl == 0x2 */);

	dr7 = 0x408;
	asm volatile("mov %0,%%dr7" : : "r" (dr7));
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0x3);

	vmx_set_test_stage(0);
	vmcall();
	report(vmx_get_test_stage() == 1, "Save debug controls");

	if (ctrl_enter_rev.set & ENT_LOAD_DBGCTLS ||
	    ctrl_exit_rev.set & EXI_SAVE_DBGCTLS) {
		printf("\tDebug controls are always loaded/saved\n");
		return;
	}
	vmx_set_test_stage(2);
	vmcall();

	asm volatile("mov %%dr7,%0" : "=r" (dr7));
	debugctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
	/* Commented out: KVM does not support DEBUGCTL so far */
	(void)debugctl;
	report(dr7 == 0x402,
	       "Guest=host debug controls" /* && debugctl == 0x1 */);

	dr7 = 0x408;
	asm volatile("mov %0,%%dr7" : : "r" (dr7));
	wrmsr(MSR_IA32_DEBUGCTLMSR, 0x3);

	vmx_set_test_stage(3);
	vmcall();
	report(vmx_get_test_stage() == 4, "Don't save debug controls");
}

static int dbgctls_exit_handler(union exit_reason exit_reason)
{
	u32 insn_len = vmcs_read(EXI_INST_LEN);
	u64 guest_rip = vmcs_read(GUEST_RIP);
	u64 dr7, debugctl;

	asm volatile("mov %%dr7,%0" : "=r" (dr7));
	debugctl = rdmsr(MSR_IA32_DEBUGCTLMSR);

	switch (exit_reason.basic) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			if (dr7 == 0x400 && debugctl == 0 &&
			    vmcs_read(GUEST_DR7) == 0x408 /* &&
			    Commented out: KVM does not support DEBUGCTL so far
			    vmcs_read(GUEST_DEBUGCTL) == 0x3 */)
				vmx_inc_test_stage();
			break;
		case 2:
			dr7 = 0x402;
			asm volatile("mov %0,%%dr7" : : "r" (dr7));
			wrmsr(MSR_IA32_DEBUGCTLMSR, 0x1);
			vmcs_write(GUEST_DR7, 0x404);
			vmcs_write(GUEST_DEBUGCTL, 0x2);

			vmcs_write(ENT_CONTROLS,
				vmcs_read(ENT_CONTROLS) & ~ENT_LOAD_DBGCTLS);
			vmcs_write(EXI_CONTROLS,
				vmcs_read(EXI_CONTROLS) & ~EXI_SAVE_DBGCTLS);
			break;
		case 3:
			if (dr7 == 0x400 && debugctl == 0 &&
			    vmcs_read(GUEST_DR7) == 0x404 /* &&
			    Commented out: KVM does not support DEBUGCTL so far
			    vmcs_read(GUEST_DEBUGCTL) == 0x2 */)
				vmx_inc_test_stage();
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		report_fail("Unknown exit reason, %d", exit_reason.full);
		print_vmexit_info(exit_reason);
	}
	return VMX_TEST_VMEXIT;
}

struct vmx_msr_entry {
	u32 index;
	u32 reserved;
	u64 value;
} __attribute__((packed));

#define MSR_MAGIC 0x31415926
struct vmx_msr_entry *exit_msr_store, *entry_msr_load, *exit_msr_load;

static int msr_switch_init(struct vmcs *vmcs)
{
	msr_bmp_init();
	exit_msr_store = alloc_page();
	exit_msr_load = alloc_page();
	entry_msr_load = alloc_page();
	entry_msr_load[0].index = MSR_KERNEL_GS_BASE;
	entry_msr_load[0].value = MSR_MAGIC;

	vmx_set_test_stage(1);
	vmcs_write(ENT_MSR_LD_CNT, 1);
	vmcs_write(ENTER_MSR_LD_ADDR, (u64)entry_msr_load);
	vmcs_write(EXI_MSR_ST_CNT, 1);
	vmcs_write(EXIT_MSR_ST_ADDR, (u64)exit_msr_store);
	vmcs_write(EXI_MSR_LD_CNT, 1);
	vmcs_write(EXIT_MSR_LD_ADDR, (u64)exit_msr_load);
	return VMX_TEST_START;
}

static void msr_switch_main(void)
{
	if (vmx_get_test_stage() == 1) {
		report(rdmsr(MSR_KERNEL_GS_BASE) == MSR_MAGIC,
		       "VM entry MSR load");
		vmx_set_test_stage(2);
		wrmsr(MSR_KERNEL_GS_BASE, MSR_MAGIC + 1);
		exit_msr_store[0].index = MSR_KERNEL_GS_BASE;
		exit_msr_load[0].index = MSR_KERNEL_GS_BASE;
		exit_msr_load[0].value = MSR_MAGIC + 2;
	}
	vmcall();
}

static int msr_switch_exit_handler(union exit_reason exit_reason)
{
	if (exit_reason.basic == VMX_VMCALL && vmx_get_test_stage() == 2) {
		report(exit_msr_store[0].value == MSR_MAGIC + 1,
		       "VM exit MSR store");
		report(rdmsr(MSR_KERNEL_GS_BASE) == MSR_MAGIC + 2,
		       "VM exit MSR load");
		vmx_set_test_stage(3);
		entry_msr_load[0].index = MSR_FS_BASE;
		return VMX_TEST_RESUME;
	}
	printf("ERROR %s: unexpected stage=%u or reason=0x%x\n",
		__func__, vmx_get_test_stage(), exit_reason.full);
	return VMX_TEST_EXIT;
}

static int msr_switch_entry_failure(struct vmentry_result *result)
{
	if (result->vm_fail) {
		printf("ERROR %s: VM-Fail on %s\n", __func__, result->instr);
		return VMX_TEST_EXIT;
	}

	if (result->exit_reason.failed_vmentry &&
	    result->exit_reason.basic == VMX_FAIL_MSR &&
	    vmx_get_test_stage() == 3) {
		report(vmcs_read(EXI_QUALIFICATION) == 1,
		       "VM entry MSR load: try to load FS_BASE");
		return VMX_TEST_VMEXIT;
	}
	printf("ERROR %s: unexpected stage=%u or reason=%x\n",
		__func__, vmx_get_test_stage(), result->exit_reason.full);
	return VMX_TEST_EXIT;
}

static int vmmcall_init(struct vmcs *vmcs)
{
	vmcs_write(EXC_BITMAP, 1 << UD_VECTOR);
	return VMX_TEST_START;
}

static void vmmcall_main(void)
{
	asm volatile(
		"mov $0xABCD, %%rax\n\t"
		"vmmcall\n\t"
		::: "rax");

	report_fail("VMMCALL");
}

static int vmmcall_exit_handler(union exit_reason exit_reason)
{
	switch (exit_reason.basic) {
	case VMX_VMCALL:
		printf("here\n");
		report_fail("VMMCALL triggers #UD");
		break;
	case VMX_EXC_NMI:
		report((vmcs_read(EXI_INTR_INFO) & 0xff) == UD_VECTOR,
		       "VMMCALL triggers #UD");
		break;
	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}

	return VMX_TEST_VMEXIT;
}

static int disable_rdtscp_init(struct vmcs *vmcs)
{
	u32 ctrl_cpu1;

	if (ctrl_cpu_rev[0].clr & CPU_SECONDARY) {
		ctrl_cpu1 = vmcs_read(CPU_EXEC_CTRL1);
		ctrl_cpu1 &= ~CPU_RDTSCP;
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu1);
	}

	return VMX_TEST_START;
}

static void disable_rdtscp_ud_handler(struct ex_regs *regs)
{
	switch (vmx_get_test_stage()) {
	case 0:
		report_pass("RDTSCP triggers #UD");
		vmx_inc_test_stage();
		regs->rip += 3;
		break;
	case 2:
		report_pass("RDPID triggers #UD");
		vmx_inc_test_stage();
		regs->rip += 4;
		break;
	}
	return;

}

static void disable_rdtscp_main(void)
{
	/* Test that #UD is properly injected in L2.  */
	handle_exception(UD_VECTOR, disable_rdtscp_ud_handler);

	vmx_set_test_stage(0);
	asm volatile("rdtscp" : : : "eax", "ecx", "edx");
	vmcall();
	asm volatile(".byte 0xf3, 0x0f, 0xc7, 0xf8" : : : "eax");

	handle_exception(UD_VECTOR, 0);
	vmcall();
}

static int disable_rdtscp_exit_handler(union exit_reason exit_reason)
{
	switch (exit_reason.basic) {
	case VMX_VMCALL:
		switch (vmx_get_test_stage()) {
		case 0:
			report_fail("RDTSCP triggers #UD");
			vmx_inc_test_stage();
			/* fallthrough */
		case 1:
			vmx_inc_test_stage();
			vmcs_write(GUEST_RIP, vmcs_read(GUEST_RIP) + 3);
			return VMX_TEST_RESUME;
		case 2:
			report_fail("RDPID triggers #UD");
			break;
		}
		break;

	default:
		report_fail("Unknown exit reason, 0x%x", exit_reason.full);
		print_vmexit_info(exit_reason);
	}
	return VMX_TEST_VMEXIT;
}

static int int3_init(struct vmcs *vmcs)
{
	vmcs_write(EXC_BITMAP, ~0u);
	return VMX_TEST_START;
}

static void int3_guest_main(void)
{
	asm volatile ("int3");
}

static int int3_exit_handler(union exit_reason exit_reason)
{
	u32 intr_info = vmcs_read(EXI_INTR_INFO);

	report(exit_reason.basic == VMX_EXC_NMI &&
	       (intr_info & INTR_INFO_VALID_MASK) &&
	       (intr_info & INTR_INFO_VECTOR_MASK) == BP_VECTOR &&
	       ((intr_info & INTR_INFO_INTR_TYPE_MASK) >>
	        INTR_INFO_INTR_TYPE_SHIFT) == VMX_INTR_TYPE_SOFT_EXCEPTION,
	       "L1 intercepts #BP");

	return VMX_TEST_VMEXIT;
}

static int into_init(struct vmcs *vmcs)
{
	vmcs_write(EXC_BITMAP, ~0u);
	return VMX_TEST_START;
}

static void into_guest_main(void)
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

static int into_exit_handler(union exit_reason exit_reason)
{
	u32 intr_info = vmcs_read(EXI_INTR_INFO);

	report(exit_reason.basic == VMX_EXC_NMI &&
	       (intr_info & INTR_INFO_VALID_MASK) &&
	       (intr_info & INTR_INFO_VECTOR_MASK) == OF_VECTOR &&
	       ((intr_info & INTR_INFO_INTR_TYPE_MASK) >>
	        INTR_INFO_INTR_TYPE_SHIFT) == VMX_INTR_TYPE_SOFT_EXCEPTION,
	       "L1 intercepts #OF");

	return VMX_TEST_VMEXIT;
}

static void exit_monitor_from_l2_main(void)
{
	printf("Calling exit(0) from l2...\n");
	exit(0);
}

static int exit_monitor_from_l2_handler(union exit_reason exit_reason)
{
	report_fail("The guest should have killed the VMM");
	return VMX_TEST_EXIT;
}

static void assert_exit_reason(u64 expected)
{
	u64 actual = vmcs_read(EXI_REASON);

	TEST_ASSERT_EQ_MSG(expected, actual, "Expected %s, got %s.",
			   exit_reason_description(expected),
			   exit_reason_description(actual));
}

static void skip_exit_insn(void)
{
	u64 guest_rip = vmcs_read(GUEST_RIP);
	u32 insn_len = vmcs_read(EXI_INST_LEN);
	vmcs_write(GUEST_RIP, guest_rip + insn_len);
}

static void skip_exit_vmcall(void)
{
	assert_exit_reason(VMX_VMCALL);
	skip_exit_insn();
}

static void v2_null_test_guest(void)
{
}

static void v2_null_test(void)
{
	test_set_guest(v2_null_test_guest);
	enter_guest();
	report_pass(__func__);
}

static void v2_multiple_entries_test_guest(void)
{
	vmx_set_test_stage(1);
	vmcall();
	vmx_set_test_stage(2);
}

static void v2_multiple_entries_test(void)
{
	test_set_guest(v2_multiple_entries_test_guest);
	enter_guest();
	TEST_ASSERT_EQ(vmx_get_test_stage(), 1);
	skip_exit_vmcall();
	enter_guest();
	TEST_ASSERT_EQ(vmx_get_test_stage(), 2);
	report_pass(__func__);
}

static int fixture_test_data = 1;

static void fixture_test_teardown(void *data)
{
	*((int *) data) = 1;
}

static void fixture_test_guest(void)
{
	fixture_test_data++;
}


static void fixture_test_setup(void)
{
	TEST_ASSERT_EQ_MSG(1, fixture_test_data,
			   "fixture_test_teardown didn't run?!");
	fixture_test_data = 2;
	test_add_teardown(fixture_test_teardown, &fixture_test_data);
	test_set_guest(fixture_test_guest);
}

static void fixture_test_case1(void)
{
	fixture_test_setup();
	TEST_ASSERT_EQ(2, fixture_test_data);
	enter_guest();
	TEST_ASSERT_EQ(3, fixture_test_data);
	report_pass(__func__);
}

static void fixture_test_case2(void)
{
	fixture_test_setup();
	TEST_ASSERT_EQ(2, fixture_test_data);
	enter_guest();
	TEST_ASSERT_EQ(3, fixture_test_data);
	report_pass(__func__);
}

enum ept_access_op {
	OP_READ,
	OP_WRITE,
	OP_EXEC,
	OP_FLUSH_TLB,
	OP_EXIT,
};

static struct ept_access_test_data {
	unsigned long gpa;
	unsigned long *gva;
	unsigned long hpa;
	unsigned long *hva;
	enum ept_access_op op;
} ept_access_test_data;

extern unsigned char ret42_start;
extern unsigned char ret42_end;

/* Returns 42. */
asm(
	".align 64\n"
	"ret42_start:\n"
	"mov $42, %eax\n"
	"ret\n"
	"ret42_end:\n"
);

static void
diagnose_ept_violation_qual(u64 expected, u64 actual)
{

#define DIAGNOSE(flag)							\
do {									\
	if ((expected & flag) != (actual & flag))			\
		printf(#flag " %sexpected\n",				\
		       (expected & flag) ? "" : "un");			\
} while (0)

	DIAGNOSE(EPT_VLT_RD);
	DIAGNOSE(EPT_VLT_WR);
	DIAGNOSE(EPT_VLT_FETCH);
	DIAGNOSE(EPT_VLT_PERM_RD);
	DIAGNOSE(EPT_VLT_PERM_WR);
	DIAGNOSE(EPT_VLT_PERM_EX);
	DIAGNOSE(EPT_VLT_LADDR_VLD);
	DIAGNOSE(EPT_VLT_PADDR);

#undef DIAGNOSE
}

static void do_ept_access_op(enum ept_access_op op)
{
	ept_access_test_data.op = op;
	enter_guest();
}

/*
 * Force the guest to flush its TLB (i.e., flush gva -> gpa mappings). Only
 * needed by tests that modify guest PTEs.
 */
static void ept_access_test_guest_flush_tlb(void)
{
	do_ept_access_op(OP_FLUSH_TLB);
	skip_exit_vmcall();
}

/*
 * Modifies the EPT entry at @level in the mapping of @gpa. First clears the
 * bits in @clear then sets the bits in @set. @mkhuge transforms the entry into
 * a huge page.
 */
static unsigned long ept_twiddle(unsigned long gpa, bool mkhuge, int level,
				 unsigned long clear, unsigned long set)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;
	unsigned long pte;

	/* Screw with the mapping at the requested level. */
	TEST_ASSERT(get_ept_pte(pml4, gpa, level, &orig_pte));
	pte = orig_pte;
	if (mkhuge)
		pte = (orig_pte & ~EPT_ADDR_MASK) | data->hpa | EPT_LARGE_PAGE;
	else
		pte = orig_pte;
	pte = (pte & ~clear) | set;
	set_ept_pte(pml4, gpa, level, pte);
	invept(INVEPT_SINGLE, eptp);

	return orig_pte;
}

static void ept_untwiddle(unsigned long gpa, int level, unsigned long orig_pte)
{
	set_ept_pte(pml4, gpa, level, orig_pte);
	invept(INVEPT_SINGLE, eptp);
}

static void do_ept_violation(bool leaf, enum ept_access_op op,
			     u64 expected_qual, u64 expected_paddr)
{
	u64 qual;

	/* Try the access and observe the violation. */
	do_ept_access_op(op);

	assert_exit_reason(VMX_EPT_VIOLATION);

	qual = vmcs_read(EXI_QUALIFICATION);

	/* Mask undefined bits (which may later be defined in certain cases). */
	qual &= ~(EPT_VLT_GUEST_USER | EPT_VLT_GUEST_RW | EPT_VLT_GUEST_EX |
		 EPT_VLT_PERM_USER_EX);

	diagnose_ept_violation_qual(expected_qual, qual);
	TEST_EXPECT_EQ(expected_qual, qual);

	#if 0
	/* Disable for now otherwise every test will fail */
	TEST_EXPECT_EQ(vmcs_read(GUEST_LINEAR_ADDRESS),
		       (unsigned long) (
			       op == OP_EXEC ? data->gva + 1 : data->gva));
	#endif
	/*
	 * TODO: tests that probe expected_paddr in pages other than the one at
	 * the beginning of the 1g region.
	 */
	TEST_EXPECT_EQ(vmcs_read(INFO_PHYS_ADDR), expected_paddr);
}

static void
ept_violation_at_level_mkhuge(bool mkhuge, int level, unsigned long clear,
			      unsigned long set, enum ept_access_op op,
			      u64 expected_qual)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;

	orig_pte = ept_twiddle(data->gpa, mkhuge, level, clear, set);

	do_ept_violation(level == 1 || mkhuge, op, expected_qual,
			 op == OP_EXEC ? data->gpa + sizeof(unsigned long) :
					 data->gpa);

	/* Fix the violation and resume the op loop. */
	ept_untwiddle(data->gpa, level, orig_pte);
	enter_guest();
	skip_exit_vmcall();
}

static void
ept_violation_at_level(int level, unsigned long clear, unsigned long set,
		       enum ept_access_op op, u64 expected_qual)
{
	ept_violation_at_level_mkhuge(false, level, clear, set, op,
				      expected_qual);
	if (ept_huge_pages_supported(level))
		ept_violation_at_level_mkhuge(true, level, clear, set, op,
					      expected_qual);
}

static void ept_violation(unsigned long clear, unsigned long set,
			  enum ept_access_op op, u64 expected_qual)
{
	ept_violation_at_level(1, clear, set, op, expected_qual);
	ept_violation_at_level(2, clear, set, op, expected_qual);
	ept_violation_at_level(3, clear, set, op, expected_qual);
	ept_violation_at_level(4, clear, set, op, expected_qual);
}

static void ept_access_violation(unsigned long access, enum ept_access_op op,
				       u64 expected_qual)
{
	ept_violation(EPT_PRESENT, access, op,
		      expected_qual | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

/*
 * For translations that don't involve a GVA, that is physical address (paddr)
 * accesses, EPT violations don't set the flag EPT_VLT_PADDR.  For a typical
 * guest memory access, the hardware does GVA -> GPA -> HPA.  However, certain
 * translations don't involve GVAs, such as when the hardware does the guest
 * page table walk. For example, in translating GVA_1 -> GPA_1, the guest MMU
 * might try to set an A bit on a guest PTE. If the GPA_2 that the PTE resides
 * on isn't present in the EPT, then the EPT violation will be for GPA_2 and
 * the EPT_VLT_PADDR bit will be clear in the exit qualification.
 *
 * Note that paddr violations can also be triggered by loading PAE page tables
 * with wonky addresses. We don't test that yet.
 *
 * This function modifies the EPT entry that maps the GPA that the guest page
 * table entry mapping ept_access_test_data.gva resides on.
 *
 *	@ept_access	EPT permissions to set. Other permissions are cleared.
 *
 *	@pte_ad		Set the A/D bits on the guest PTE accordingly.
 *
 *	@op		Guest operation to perform with
 *			ept_access_test_data.gva.
 *
 *	@expect_violation
 *			Is a violation expected during the paddr access?
 *
 *	@expected_qual	Expected qualification for the EPT violation.
 *			EPT_VLT_PADDR should be clear.
 */
static void ept_access_paddr(unsigned long ept_access, unsigned long pte_ad,
			     enum ept_access_op op, bool expect_violation,
			     u64 expected_qual)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long *ptep;
	unsigned long gpa;
	unsigned long orig_epte;
	unsigned long epte;
	int i;

	/* Modify the guest PTE mapping data->gva according to @pte_ad.  */
	ptep = get_pte_level(current_page_table(), data->gva, /*level=*/1);
	TEST_ASSERT(ptep);
	TEST_ASSERT_EQ(*ptep & PT_ADDR_MASK, data->gpa);
	*ptep = (*ptep & ~PT_AD_MASK) | pte_ad;
	ept_access_test_guest_flush_tlb();

	/*
	 * Now modify the access bits on the EPT entry for the GPA that the
	 * guest PTE resides on. Note that by modifying a single EPT entry,
	 * we're potentially affecting 512 guest PTEs. However, we've carefully
	 * constructed our test such that those other 511 PTEs aren't used by
	 * the guest: data->gva is at the beginning of a 1G huge page, thus the
	 * PTE we're modifying is at the beginning of a 4K page and the
	 * following 511 entries are also under our control (and not touched by
	 * the guest).
	 */
	gpa = virt_to_phys(ptep);
	TEST_ASSERT_EQ(gpa & ~PAGE_MASK, 0);
	/*
	 * Make sure the guest page table page is mapped with a 4K EPT entry,
	 * otherwise our level=1 twiddling below will fail. We use the
	 * identity map (gpa = gpa) since page tables are shared with the host.
	 */
	install_ept(pml4, gpa, gpa, EPT_PRESENT);
	orig_epte = ept_twiddle(gpa, /*mkhuge=*/0, /*level=*/1,
				/*clear=*/EPT_PRESENT, /*set=*/ept_access);

	if (expect_violation) {
		do_ept_violation(/*leaf=*/true, op,
				 expected_qual | EPT_VLT_LADDR_VLD, gpa);
		ept_untwiddle(gpa, /*level=*/1, orig_epte);
		do_ept_access_op(op);
	} else {
		do_ept_access_op(op);
		if (ept_ad_enabled()) {
			for (i = EPT_PAGE_LEVEL; i > 0; i--) {
				TEST_ASSERT(get_ept_pte(pml4, gpa, i, &epte));
				TEST_ASSERT(epte & EPT_ACCESS_FLAG);
				if (i == 1)
					TEST_ASSERT(epte & EPT_DIRTY_FLAG);
				else
					TEST_ASSERT_EQ(epte & EPT_DIRTY_FLAG, 0);
			}
		}

		ept_untwiddle(gpa, /*level=*/1, orig_epte);
	}

	TEST_ASSERT(*ptep & PT_ACCESSED_MASK);
	if ((pte_ad & PT_DIRTY_MASK) || op == OP_WRITE)
		TEST_ASSERT(*ptep & PT_DIRTY_MASK);

	skip_exit_vmcall();
}

static void ept_access_allowed_paddr(unsigned long ept_access,
				     unsigned long pte_ad,
				     enum ept_access_op op)
{
	ept_access_paddr(ept_access, pte_ad, op, /*expect_violation=*/false,
			 /*expected_qual=*/-1);
}

static void ept_access_violation_paddr(unsigned long ept_access,
				       unsigned long pte_ad,
				       enum ept_access_op op,
				       u64 expected_qual)
{
	ept_access_paddr(ept_access, pte_ad, op, /*expect_violation=*/true,
			 expected_qual);
}


static void ept_allowed_at_level_mkhuge(bool mkhuge, int level,
					unsigned long clear,
					unsigned long set,
					enum ept_access_op op)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;

	orig_pte = ept_twiddle(data->gpa, mkhuge, level, clear, set);

	/* No violation. Should proceed to vmcall. */
	do_ept_access_op(op);
	skip_exit_vmcall();

	ept_untwiddle(data->gpa, level, orig_pte);
}

static void ept_allowed_at_level(int level, unsigned long clear,
				 unsigned long set, enum ept_access_op op)
{
	ept_allowed_at_level_mkhuge(false, level, clear, set, op);
	if (ept_huge_pages_supported(level))
		ept_allowed_at_level_mkhuge(true, level, clear, set, op);
}

static void ept_allowed(unsigned long clear, unsigned long set,
			enum ept_access_op op)
{
	ept_allowed_at_level(1, clear, set, op);
	ept_allowed_at_level(2, clear, set, op);
	ept_allowed_at_level(3, clear, set, op);
	ept_allowed_at_level(4, clear, set, op);
}

static void ept_ignored_bit(int bit)
{
	/* Set the bit. */
	ept_allowed(0, 1ul << bit, OP_READ);
	ept_allowed(0, 1ul << bit, OP_WRITE);
	ept_allowed(0, 1ul << bit, OP_EXEC);

	/* Clear the bit. */
	ept_allowed(1ul << bit, 0, OP_READ);
	ept_allowed(1ul << bit, 0, OP_WRITE);
	ept_allowed(1ul << bit, 0, OP_EXEC);
}

static void ept_access_allowed(unsigned long access, enum ept_access_op op)
{
	ept_allowed(EPT_PRESENT, access, op);
}


static void ept_misconfig_at_level_mkhuge_op(bool mkhuge, int level,
					     unsigned long clear,
					     unsigned long set,
					     enum ept_access_op op)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long orig_pte;

	orig_pte = ept_twiddle(data->gpa, mkhuge, level, clear, set);

	do_ept_access_op(op);
	assert_exit_reason(VMX_EPT_MISCONFIG);

	/* Intel 27.2.1, "For all other VM exits, this field is cleared." */
	#if 0
	/* broken: */
	TEST_EXPECT_EQ_MSG(vmcs_read(EXI_QUALIFICATION), 0);
	#endif
	#if 0
	/*
	 * broken:
	 * According to description of exit qual for EPT violation,
	 * EPT_VLT_LADDR_VLD indicates if GUEST_LINEAR_ADDRESS is valid.
	 * However, I can't find anything that says GUEST_LINEAR_ADDRESS ought
	 * to be set for msiconfig.
	 */
	TEST_EXPECT_EQ(vmcs_read(GUEST_LINEAR_ADDRESS),
		       (unsigned long) (
			       op == OP_EXEC ? data->gva + 1 : data->gva));
	#endif

	/* Fix the violation and resume the op loop. */
	ept_untwiddle(data->gpa, level, orig_pte);
	enter_guest();
	skip_exit_vmcall();
}

static void ept_misconfig_at_level_mkhuge(bool mkhuge, int level,
					  unsigned long clear,
					  unsigned long set)
{
	/* The op shouldn't matter (read, write, exec), so try them all! */
	ept_misconfig_at_level_mkhuge_op(mkhuge, level, clear, set, OP_READ);
	ept_misconfig_at_level_mkhuge_op(mkhuge, level, clear, set, OP_WRITE);
	ept_misconfig_at_level_mkhuge_op(mkhuge, level, clear, set, OP_EXEC);
}

static void ept_misconfig_at_level(int level, unsigned long clear,
				   unsigned long set)
{
	ept_misconfig_at_level_mkhuge(false, level, clear, set);
	if (ept_huge_pages_supported(level))
		ept_misconfig_at_level_mkhuge(true, level, clear, set);
}

static void ept_misconfig(unsigned long clear, unsigned long set)
{
	ept_misconfig_at_level(1, clear, set);
	ept_misconfig_at_level(2, clear, set);
	ept_misconfig_at_level(3, clear, set);
	ept_misconfig_at_level(4, clear, set);
}

static void ept_access_misconfig(unsigned long access)
{
	ept_misconfig(EPT_PRESENT, access);
}

static void ept_reserved_bit_at_level_nohuge(int level, int bit)
{
	/* Setting the bit causes a misconfig. */
	ept_misconfig_at_level_mkhuge(false, level, 0, 1ul << bit);

	/* Making the entry non-present turns reserved bits into ignored. */
	ept_violation_at_level(level, EPT_PRESENT, 1ul << bit, OP_READ,
			       EPT_VLT_RD | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

static void ept_reserved_bit_at_level_huge(int level, int bit)
{
	/* Setting the bit causes a misconfig. */
	ept_misconfig_at_level_mkhuge(true, level, 0, 1ul << bit);

	/* Making the entry non-present turns reserved bits into ignored. */
	ept_violation_at_level(level, EPT_PRESENT, 1ul << bit, OP_READ,
			       EPT_VLT_RD | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

static void ept_reserved_bit_at_level(int level, int bit)
{
	/* Setting the bit causes a misconfig. */
	ept_misconfig_at_level(level, 0, 1ul << bit);

	/* Making the entry non-present turns reserved bits into ignored. */
	ept_violation_at_level(level, EPT_PRESENT, 1ul << bit, OP_READ,
			       EPT_VLT_RD | EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
}

static void ept_reserved_bit(int bit)
{
	ept_reserved_bit_at_level(1, bit);
	ept_reserved_bit_at_level(2, bit);
	ept_reserved_bit_at_level(3, bit);
	ept_reserved_bit_at_level(4, bit);
}

#define PAGE_2M_ORDER 9
#define PAGE_1G_ORDER 18

static void *get_1g_page(void)
{
	static void *alloc;

	if (!alloc)
		alloc = alloc_pages(PAGE_1G_ORDER);
	return alloc;
}

static void ept_access_test_teardown(void *unused)
{
	/* Exit the guest cleanly. */
	do_ept_access_op(OP_EXIT);
}

static void ept_access_test_guest(void)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	int (*code)(void) = (int (*)(void)) &data->gva[1];

	while (true) {
		switch (data->op) {
		case OP_READ:
			TEST_ASSERT_EQ(*data->gva, MAGIC_VAL_1);
			break;
		case OP_WRITE:
			*data->gva = MAGIC_VAL_2;
			TEST_ASSERT_EQ(*data->gva, MAGIC_VAL_2);
			*data->gva = MAGIC_VAL_1;
			break;
		case OP_EXEC:
			TEST_ASSERT_EQ(42, code());
			break;
		case OP_FLUSH_TLB:
			write_cr3(read_cr3());
			break;
		case OP_EXIT:
			return;
		default:
			TEST_ASSERT_MSG(false, "Unknown op %d", data->op);
		}
		vmcall();
	}
}

static void ept_access_test_setup(void)
{
	struct ept_access_test_data *data = &ept_access_test_data;
	unsigned long npages = 1ul << PAGE_1G_ORDER;
	unsigned long size = npages * PAGE_SIZE;
	unsigned long *page_table = current_page_table();
	unsigned long pte;

	if (setup_ept(false))
		test_skip("EPT not supported");

	/* We use data->gpa = 1 << 39 so that test data has a separate pml4 entry */
	if (cpuid_maxphyaddr() < 40)
		test_skip("Test needs MAXPHYADDR >= 40");

	test_set_guest(ept_access_test_guest);
	test_add_teardown(ept_access_test_teardown, NULL);

	data->hva = get_1g_page();
	TEST_ASSERT(data->hva);
	data->hpa = virt_to_phys(data->hva);

	data->gpa = 1ul << 39;
	data->gva = (void *) ALIGN((unsigned long) alloc_vpages(npages * 2),
				   size);
	TEST_ASSERT(!any_present_pages(page_table, data->gva, size));
	install_pages(page_table, data->gpa, size, data->gva);

	/*
	 * Make sure nothing's mapped here so the tests that screw with the
	 * pml4 entry don't inadvertently break something.
	 */
	TEST_ASSERT(get_ept_pte(pml4, data->gpa, 4, &pte) && pte == 0);
	TEST_ASSERT(get_ept_pte(pml4, data->gpa + size - 1, 4, &pte) && pte == 0);
	install_ept(pml4, data->hpa, data->gpa, EPT_PRESENT);

	data->hva[0] = MAGIC_VAL_1;
	memcpy(&data->hva[1], &ret42_start, &ret42_end - &ret42_start);
}

static void ept_access_test_not_present(void)
{
	ept_access_test_setup();
	/* --- */
	ept_access_violation(0, OP_READ, EPT_VLT_RD);
	ept_access_violation(0, OP_WRITE, EPT_VLT_WR);
	ept_access_violation(0, OP_EXEC, EPT_VLT_FETCH);
}

static void ept_access_test_read_only(void)
{
	ept_access_test_setup();

	/* r-- */
	ept_access_allowed(EPT_RA, OP_READ);
	ept_access_violation(EPT_RA, OP_WRITE, EPT_VLT_WR | EPT_VLT_PERM_RD);
	ept_access_violation(EPT_RA, OP_EXEC, EPT_VLT_FETCH | EPT_VLT_PERM_RD);
}

static void ept_access_test_write_only(void)
{
	ept_access_test_setup();
	/* -w- */
	ept_access_misconfig(EPT_WA);
}

static void ept_access_test_read_write(void)
{
	ept_access_test_setup();
	/* rw- */
	ept_access_allowed(EPT_RA | EPT_WA, OP_READ);
	ept_access_allowed(EPT_RA | EPT_WA, OP_WRITE);
	ept_access_violation(EPT_RA | EPT_WA, OP_EXEC,
			   EPT_VLT_FETCH | EPT_VLT_PERM_RD | EPT_VLT_PERM_WR);
}


static void ept_access_test_execute_only(void)
{
	ept_access_test_setup();
	/* --x */
	if (ept_execute_only_supported()) {
		ept_access_violation(EPT_EA, OP_READ,
				     EPT_VLT_RD | EPT_VLT_PERM_EX);
		ept_access_violation(EPT_EA, OP_WRITE,
				     EPT_VLT_WR | EPT_VLT_PERM_EX);
		ept_access_allowed(EPT_EA, OP_EXEC);
	} else {
		ept_access_misconfig(EPT_EA);
	}
}

static void ept_access_test_read_execute(void)
{
	ept_access_test_setup();
	/* r-x */
	ept_access_allowed(EPT_RA | EPT_EA, OP_READ);
	ept_access_violation(EPT_RA | EPT_EA, OP_WRITE,
			   EPT_VLT_WR | EPT_VLT_PERM_RD | EPT_VLT_PERM_EX);
	ept_access_allowed(EPT_RA | EPT_EA, OP_EXEC);
}

static void ept_access_test_write_execute(void)
{
	ept_access_test_setup();
	/* -wx */
	ept_access_misconfig(EPT_WA | EPT_EA);
}

static void ept_access_test_read_write_execute(void)
{
	ept_access_test_setup();
	/* rwx */
	ept_access_allowed(EPT_RA | EPT_WA | EPT_EA, OP_READ);
	ept_access_allowed(EPT_RA | EPT_WA | EPT_EA, OP_WRITE);
	ept_access_allowed(EPT_RA | EPT_WA | EPT_EA, OP_EXEC);
}

static void ept_access_test_reserved_bits(void)
{
	int i;
	int maxphyaddr;

	ept_access_test_setup();

	/* Reserved bits above maxphyaddr. */
	maxphyaddr = cpuid_maxphyaddr();
	for (i = maxphyaddr; i <= 51; i++) {
		report_prefix_pushf("reserved_bit=%d", i);
		ept_reserved_bit(i);
		report_prefix_pop();
	}

	/* Level-specific reserved bits. */
	ept_reserved_bit_at_level_nohuge(2, 3);
	ept_reserved_bit_at_level_nohuge(2, 4);
	ept_reserved_bit_at_level_nohuge(2, 5);
	ept_reserved_bit_at_level_nohuge(2, 6);
	/* 2M alignment. */
	for (i = 12; i < 20; i++) {
		report_prefix_pushf("reserved_bit=%d", i);
		ept_reserved_bit_at_level_huge(2, i);
		report_prefix_pop();
	}
	ept_reserved_bit_at_level_nohuge(3, 3);
	ept_reserved_bit_at_level_nohuge(3, 4);
	ept_reserved_bit_at_level_nohuge(3, 5);
	ept_reserved_bit_at_level_nohuge(3, 6);
	/* 1G alignment. */
	for (i = 12; i < 29; i++) {
		report_prefix_pushf("reserved_bit=%d", i);
		ept_reserved_bit_at_level_huge(3, i);
		report_prefix_pop();
	}
	ept_reserved_bit_at_level(4, 3);
	ept_reserved_bit_at_level(4, 4);
	ept_reserved_bit_at_level(4, 5);
	ept_reserved_bit_at_level(4, 6);
	ept_reserved_bit_at_level(4, 7);
}

static void ept_access_test_ignored_bits(void)
{
	ept_access_test_setup();
	/*
	 * Bits ignored at every level. Bits 8 and 9 (A and D) are ignored as
	 * far as translation is concerned even if AD bits are enabled in the
	 * EPTP. Bit 63 is ignored because "EPT-violation #VE" VM-execution
	 * control is 0.
	 */
	ept_ignored_bit(8);
	ept_ignored_bit(9);
	ept_ignored_bit(10);
	ept_ignored_bit(11);
	ept_ignored_bit(52);
	ept_ignored_bit(53);
	ept_ignored_bit(54);
	ept_ignored_bit(55);
	ept_ignored_bit(56);
	ept_ignored_bit(57);
	ept_ignored_bit(58);
	ept_ignored_bit(59);
	ept_ignored_bit(60);
	ept_ignored_bit(61);
	ept_ignored_bit(62);
	ept_ignored_bit(63);
}

static void ept_access_test_paddr_not_present_ad_disabled(void)
{
	ept_access_test_setup();
	ept_disable_ad_bits();

	ept_access_violation_paddr(0, PT_AD_MASK, OP_READ, EPT_VLT_RD);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_WRITE, EPT_VLT_RD);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_EXEC, EPT_VLT_RD);
}

static void ept_access_test_paddr_not_present_ad_enabled(void)
{
	u64 qual = EPT_VLT_RD | EPT_VLT_WR;

	ept_access_test_setup();
	ept_enable_ad_bits_or_skip_test();

	ept_access_violation_paddr(0, PT_AD_MASK, OP_READ, qual);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(0, PT_AD_MASK, OP_EXEC, qual);
}

static void ept_access_test_paddr_read_only_ad_disabled(void)
{
	/*
	 * When EPT AD bits are disabled, all accesses to guest paging
	 * structures are reported separately as a read and (after
	 * translation of the GPA to host physical address) a read+write
	 * if the A/D bits have to be set.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD;

	ept_access_test_setup();
	ept_disable_ad_bits();

	/* Can't update A bit, so all accesses fail. */
	ept_access_violation_paddr(EPT_RA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_EXEC, qual);
	/* AD bits disabled, so only writes try to update the D bit. */
	ept_access_allowed_paddr(EPT_RA, PT_ACCESSED_MASK, OP_READ);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_allowed_paddr(EPT_RA, PT_ACCESSED_MASK, OP_EXEC);
	/* Both A and D already set, so read-only is OK. */
	ept_access_allowed_paddr(EPT_RA, PT_AD_MASK, OP_READ);
	ept_access_allowed_paddr(EPT_RA, PT_AD_MASK, OP_WRITE);
	ept_access_allowed_paddr(EPT_RA, PT_AD_MASK, OP_EXEC);
}

static void ept_access_test_paddr_read_only_ad_enabled(void)
{
	/*
	 * When EPT AD bits are enabled, all accesses to guest paging
	 * structures are considered writes as far as EPT translation
	 * is concerned.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD;

	ept_access_test_setup();
	ept_enable_ad_bits_or_skip_test();

	ept_access_violation_paddr(EPT_RA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, 0, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, PT_ACCESSED_MASK, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA, PT_AD_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA, PT_AD_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA, PT_AD_MASK, OP_EXEC, qual);
}

static void ept_access_test_paddr_read_write(void)
{
	ept_access_test_setup();
	/* Read-write access to paging structure. */
	ept_access_allowed_paddr(EPT_RA | EPT_WA, 0, OP_READ);
	ept_access_allowed_paddr(EPT_RA | EPT_WA, 0, OP_WRITE);
	ept_access_allowed_paddr(EPT_RA | EPT_WA, 0, OP_EXEC);
}

static void ept_access_test_paddr_read_write_execute(void)
{
	ept_access_test_setup();
	/* RWX access to paging structure. */
	ept_access_allowed_paddr(EPT_PRESENT, 0, OP_READ);
	ept_access_allowed_paddr(EPT_PRESENT, 0, OP_WRITE);
	ept_access_allowed_paddr(EPT_PRESENT, 0, OP_EXEC);
}

static void ept_access_test_paddr_read_execute_ad_disabled(void)
{
  	/*
	 * When EPT AD bits are disabled, all accesses to guest paging
	 * structures are reported separately as a read and (after
	 * translation of the GPA to host physical address) a read+write
	 * if the A/D bits have to be set.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD | EPT_VLT_PERM_EX;

	ept_access_test_setup();
	ept_disable_ad_bits();

	/* Can't update A bit, so all accesses fail. */
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_EXEC, qual);
	/* AD bits disabled, so only writes try to update the D bit. */
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_READ);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_EXEC);
	/* Both A and D already set, so read-only is OK. */
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_READ);
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_WRITE);
	ept_access_allowed_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_EXEC);
}

static void ept_access_test_paddr_read_execute_ad_enabled(void)
{
	/*
	 * When EPT AD bits are enabled, all accesses to guest paging
	 * structures are considered writes as far as EPT translation
	 * is concerned.
	 */
	u64 qual = EPT_VLT_WR | EPT_VLT_RD | EPT_VLT_PERM_RD | EPT_VLT_PERM_EX;

	ept_access_test_setup();
	ept_enable_ad_bits_or_skip_test();

	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, 0, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_ACCESSED_MASK, OP_EXEC, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_READ, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_WRITE, qual);
	ept_access_violation_paddr(EPT_RA | EPT_EA, PT_AD_MASK, OP_EXEC, qual);
}

static void ept_access_test_paddr_not_present_page_fault(void)
{
	ept_access_test_setup();
	/*
	 * TODO: test no EPT violation as long as guest PF occurs. e.g., GPA is
	 * page is read-only in EPT but GVA is also mapped read only in PT.
	 * Thus guest page fault before host takes EPT violation for trying to
	 * update A bit.
	 */
}

static void ept_access_test_force_2m_page(void)
{
	ept_access_test_setup();

	TEST_ASSERT_EQ(ept_2m_supported(), true);
	ept_allowed_at_level_mkhuge(true, 2, 0, 0, OP_READ);
	ept_violation_at_level_mkhuge(true, 2, EPT_PRESENT, EPT_RA, OP_WRITE,
				      EPT_VLT_WR | EPT_VLT_PERM_RD |
				      EPT_VLT_LADDR_VLD | EPT_VLT_PADDR);
	ept_misconfig_at_level_mkhuge(true, 2, EPT_PRESENT, EPT_WA);
}

static bool invvpid_valid(u64 type, u64 vpid, u64 gla)
{
	if (!is_invvpid_type_supported(type))
		return false;

	if (vpid >> 16)
		return false;

	if (type != INVVPID_ALL && !vpid)
		return false;

	if (type == INVVPID_ADDR && !is_canonical(gla))
		return false;

	return true;
}

static void try_invvpid(u64 type, u64 vpid, u64 gla)
{
	int rc;
	bool valid = invvpid_valid(type, vpid, gla);
	u64 expected = valid ? VMXERR_UNSUPPORTED_VMCS_COMPONENT
		: VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID;
	/*
	 * Set VMX_INST_ERROR to VMXERR_UNVALID_VMCS_COMPONENT, so
	 * that we can tell if it is updated by INVVPID.
	 */
	vmcs_read(~0);
	rc = __invvpid(type, vpid, gla);
	report(!rc == valid, "INVVPID type %ld VPID %lx GLA %lx %s", type,
	       vpid, gla,
	       valid ? "passes" : "fails");
	report(vmcs_read(VMX_INST_ERROR) == expected,
	       "After %s INVVPID, VMX_INST_ERR is %ld (actual %ld)",
	       rc ? "failed" : "successful",
	       expected, vmcs_read(VMX_INST_ERROR));
}

static inline unsigned long get_first_supported_invvpid_type(void)
{
	u64 type = ffs(ept_vpid.val >> VPID_CAP_INVVPID_TYPES_SHIFT) - 1;

	__TEST_ASSERT(type >= INVVPID_ADDR && type <= INVVPID_CONTEXT_LOCAL);
	return type;
}

static void ds_invvpid(void *data)
{
	asm volatile("invvpid %0, %1"
		     :
		     : "m"(*(struct invvpid_operand *)data),
		       "r"(get_first_supported_invvpid_type()));
}

/*
 * The SS override is ignored in 64-bit mode, so we use an addressing
 * mode with %rsp as the base register to generate an implicit SS
 * reference.
 */
static void ss_invvpid(void *data)
{
	asm volatile("sub %%rsp,%0; invvpid (%%rsp,%0,1), %1"
		     : "+r"(data)
		     : "r"(get_first_supported_invvpid_type()));
}

static void invvpid_test_gp(void)
{
	bool fault;

	fault = test_for_exception(GP_VECTOR, &ds_invvpid,
				   (void *)NONCANONICAL);
	report(fault, "INVVPID with non-canonical DS operand raises #GP");
}

static void invvpid_test_ss(void)
{
	bool fault;

	fault = test_for_exception(SS_VECTOR, &ss_invvpid,
				   (void *)NONCANONICAL);
	report(fault, "INVVPID with non-canonical SS operand raises #SS");
}

static void invvpid_test_pf(void)
{
	void *vpage = alloc_vpage();
	bool fault;

	fault = test_for_exception(PF_VECTOR, &ds_invvpid, vpage);
	report(fault, "INVVPID with unmapped operand raises #PF");
}

static void try_compat_invvpid(void *unused)
{
	struct far_pointer32 fp = {
		.offset = (uintptr_t)&&invvpid,
		.selector = KERNEL_CS32,
	};
	uintptr_t rsp;

	asm volatile ("mov %%rsp, %0" : "=r"(rsp));

	TEST_ASSERT_MSG(fp.offset == (uintptr_t)&&invvpid,
			"Code address too high.");
	TEST_ASSERT_MSG(rsp == (u32)rsp, "Stack address too high.");

	asm goto ("lcall *%0" : : "m" (fp) : "rax" : invvpid);
	return;
invvpid:
	asm volatile (".code32;"
		      "invvpid (%eax), %eax;"
		      "lret;"
		      ".code64");
	__builtin_unreachable();
}

static void invvpid_test_compatibility_mode(void)
{
	bool fault;

	fault = test_for_exception(UD_VECTOR, &try_compat_invvpid, NULL);
	report(fault, "Compatibility mode INVVPID raises #UD");
}

static void invvpid_test_not_in_vmx_operation(void)
{
	bool fault;

	TEST_ASSERT(!vmx_off());
	fault = test_for_exception(UD_VECTOR, &ds_invvpid, NULL);
	report(fault, "INVVPID outside of VMX operation raises #UD");
	TEST_ASSERT(!vmx_on());
}

/*
 * This does not test real-address mode, virtual-8086 mode, protected mode,
 * or CPL > 0.
 */
static void invvpid_test(void)
{
	int i;
	unsigned types = 0;
	unsigned type;

	if (!is_vpid_supported())
		test_skip("VPID not supported");

	if (!is_invvpid_supported())
		test_skip("INVVPID not supported.\n");

	if (is_invvpid_type_supported(INVVPID_ADDR))
		types |= 1u << INVVPID_ADDR;
	if (is_invvpid_type_supported(INVVPID_CONTEXT_GLOBAL))
		types |= 1u << INVVPID_CONTEXT_GLOBAL;
	if (is_invvpid_type_supported(INVVPID_ALL))
		types |= 1u << INVVPID_ALL;
	if (is_invvpid_type_supported(INVVPID_CONTEXT_LOCAL))
		types |= 1u << INVVPID_CONTEXT_LOCAL;

	if (!types)
		test_skip("No INVVPID types supported.\n");

	for (i = -127; i < 128; i++)
		try_invvpid(i, 0xffff, 0);

	/*
	 * VPID must not be more than 16 bits.
	 */
	for (i = 0; i < 64; i++)
		for (type = 0; type < 4; type++)
			if (types & (1u << type))
				try_invvpid(type, 1ul << i, 0);

	/*
	 * VPID must not be zero, except for "all contexts."
	 */
	for (type = 0; type < 4; type++)
		if (types & (1u << type))
			try_invvpid(type, 0, 0);

	/*
	 * The gla operand is only validated for single-address INVVPID.
	 */
	if (types & (1u << INVVPID_ADDR))
		try_invvpid(INVVPID_ADDR, 0xffff, NONCANONICAL);

	invvpid_test_gp();
	invvpid_test_ss();
	invvpid_test_pf();
	invvpid_test_compatibility_mode();
	invvpid_test_not_in_vmx_operation();
}

/*
 * Test for early VMLAUNCH failure. Returns true if VMLAUNCH makes it
 * at least as far as the guest-state checks. Returns false if the
 * VMLAUNCH fails early and execution falls through to the next
 * instruction.
 */
static bool vmlaunch_succeeds(void)
{
	u32 exit_reason;

	/*
	 * Indirectly set VMX_INST_ERR to 12 ("VMREAD/VMWRITE from/to
	 * unsupported VMCS component"). The caller can then check
	 * to see if a failed VM-entry sets VMX_INST_ERR as expected.
	 */
	vmcs_write(~0u, 0);

	vmcs_write(HOST_RIP, (uintptr_t)&&success);
	__asm__ __volatile__ goto ("vmwrite %%rsp, %0; vmlaunch"
				   :
				   : "r" ((u64)HOST_RSP)
				   : "cc", "memory"
				   : success);
	return false;
success:
	exit_reason = vmcs_read(EXI_REASON);
	TEST_ASSERT(exit_reason == (VMX_FAIL_STATE | VMX_ENTRY_FAILURE) ||
		    exit_reason == (VMX_FAIL_MSR | VMX_ENTRY_FAILURE));
	return true;
}

/*
 * Try to launch the current VMCS.
 */
static void test_vmx_vmlaunch(u32 xerror)
{
	bool success = vmlaunch_succeeds();
	u32 vmx_inst_err;

	report(success == !xerror, "vmlaunch %s",
	       !xerror ? "succeeds" : "fails");
	if (!success && xerror) {
		vmx_inst_err = vmcs_read(VMX_INST_ERROR);
		report(vmx_inst_err == xerror,
		       "VMX inst error is %d (actual %d)", xerror,
		       vmx_inst_err);
	}
}

/*
 * Try to launch the current VMCS, and expect one of two possible
 * errors (or success) codes.
 */
static void test_vmx_vmlaunch2(u32 xerror1, u32 xerror2)
{
	bool success = vmlaunch_succeeds();
	u32 vmx_inst_err;

	if (!xerror1 == !xerror2)
		report(success == !xerror1, "vmlaunch %s",
		       !xerror1 ? "succeeds" : "fails");

	if (!success && (xerror1 || xerror2)) {
		vmx_inst_err = vmcs_read(VMX_INST_ERROR);
		report(vmx_inst_err == xerror1 || vmx_inst_err == xerror2,
		       "VMX inst error is %d or %d (actual %d)", xerror1,
		       xerror2, vmx_inst_err);
	}
}

static void test_vmx_invalid_controls(void)
{
	test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_CONTROL_FIELD);
}

static void test_vmx_valid_controls(void)
{
	test_vmx_vmlaunch(0);
}

/*
 * Test a particular value of a VM-execution control bit, if the value
 * is required or if the value is zero.
 */
static void test_rsvd_ctl_bit_value(const char *name, union vmx_ctrl_msr msr,
				    enum Encoding encoding, unsigned bit,
				    unsigned val)
{
	u32 mask = 1u << bit;
	bool expected;
	u32 controls;

	if (msr.set & mask)
		TEST_ASSERT(msr.clr & mask);

	/*
	 * We can't arbitrarily turn on a control bit, because it may
	 * introduce dependencies on other VMCS fields. So, we only
	 * test turning on bits that have a required setting.
	 */
	if (val && (msr.clr & mask) && !(msr.set & mask))
		return;

	report_prefix_pushf("%s %s bit %d",
			    val ? "Set" : "Clear", name, bit);

	controls = vmcs_read(encoding);
	if (val) {
		vmcs_write(encoding, msr.set | mask);
		expected = (msr.clr & mask);
	} else {
		vmcs_write(encoding, msr.set & ~mask);
		expected = !(msr.set & mask);
	}
	if (expected)
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	vmcs_write(encoding, controls);
	report_prefix_pop();
}

/*
 * Test reserved values of a VM-execution control bit, based on the
 * allowed bit settings from the corresponding VMX capability MSR.
 */
static void test_rsvd_ctl_bit(const char *name, union vmx_ctrl_msr msr,
			      enum Encoding encoding, unsigned bit)
{
	test_rsvd_ctl_bit_value(name, msr, encoding, bit, 0);
	test_rsvd_ctl_bit_value(name, msr, encoding, bit, 1);
}

/*
 * Reserved bits in the pin-based VM-execution controls must be set
 * properly. Software may consult the VMX capability MSRs to determine
 * the proper settings.
 * [Intel SDM]
 */
static void test_pin_based_ctls(void)
{
	unsigned bit;

	printf("%s: %lx\n", basic.ctrl ? "MSR_IA32_VMX_TRUE_PIN" :
	       "MSR_IA32_VMX_PINBASED_CTLS", ctrl_pin_rev.val);
	for (bit = 0; bit < 32; bit++)
		test_rsvd_ctl_bit("pin-based controls",
				  ctrl_pin_rev, PIN_CONTROLS, bit);
}

/*
 * Reserved bits in the primary processor-based VM-execution controls
 * must be set properly. Software may consult the VMX capability MSRs
 * to determine the proper settings.
 * [Intel SDM]
 */
static void test_primary_processor_based_ctls(void)
{
	unsigned bit;

	printf("\n%s: %lx\n", basic.ctrl ? "MSR_IA32_VMX_TRUE_PROC" :
	       "MSR_IA32_VMX_PROCBASED_CTLS", ctrl_cpu_rev[0].val);
	for (bit = 0; bit < 32; bit++)
		test_rsvd_ctl_bit("primary processor-based controls",
				  ctrl_cpu_rev[0], CPU_EXEC_CTRL0, bit);
}

/*
 * If the "activate secondary controls" primary processor-based
 * VM-execution control is 1, reserved bits in the secondary
 * processor-based VM-execution controls must be cleared. Software may
 * consult the VMX capability MSRs to determine which bits are
 * reserved.
 * If the "activate secondary controls" primary processor-based
 * VM-execution control is 0 (or if the processor does not support the
 * 1-setting of that control), no checks are performed on the
 * secondary processor-based VM-execution controls.
 * [Intel SDM]
 */
static void test_secondary_processor_based_ctls(void)
{
	u32 primary;
	u32 secondary;
	unsigned bit;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY))
		return;

	primary = vmcs_read(CPU_EXEC_CTRL0);
	secondary = vmcs_read(CPU_EXEC_CTRL1);

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY);
	printf("\nMSR_IA32_VMX_PROCBASED_CTLS2: %lx\n", ctrl_cpu_rev[1].val);
	for (bit = 0; bit < 32; bit++)
		test_rsvd_ctl_bit("secondary processor-based controls",
				  ctrl_cpu_rev[1], CPU_EXEC_CTRL1, bit);

	/*
	 * When the "activate secondary controls" VM-execution control
	 * is clear, there are no checks on the secondary controls.
	 */
	vmcs_write(CPU_EXEC_CTRL0, primary & ~CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, ~0);
	report(vmlaunch_succeeds(),
	       "Secondary processor-based controls ignored");
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	vmcs_write(CPU_EXEC_CTRL0, primary);
}

static void try_cr3_target_count(unsigned i, unsigned max)
{
	report_prefix_pushf("CR3 target count 0x%x", i);
	vmcs_write(CR3_TARGET_COUNT, i);
	if (i <= max)
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	report_prefix_pop();
}

/*
 * The CR3-target count must not be greater than 4. Future processors
 * may support a different number of CR3-target values. Software
 * should read the VMX capability MSR IA32_VMX_MISC to determine the
 * number of values supported.
 * [Intel SDM]
 */
static void test_cr3_targets(void)
{
	unsigned supported_targets = (rdmsr(MSR_IA32_VMX_MISC) >> 16) & 0x1ff;
	u32 cr3_targets = vmcs_read(CR3_TARGET_COUNT);
	unsigned i;

	printf("\nSupported CR3 targets: %d\n", supported_targets);
	TEST_ASSERT(supported_targets <= 256);

	try_cr3_target_count(-1u, supported_targets);
	try_cr3_target_count(0x80000000, supported_targets);
	try_cr3_target_count(0x7fffffff, supported_targets);
	for (i = 0; i <= supported_targets + 1; i++)
		try_cr3_target_count(i, supported_targets);
	vmcs_write(CR3_TARGET_COUNT, cr3_targets);

	/* VMWRITE to nonexistent target fields should fail. */
	for (i = supported_targets; i < 256; i++)
		TEST_ASSERT(vmcs_write(CR3_TARGET_0 + i*2, 0));
}

/*
 * Test a particular address setting in the VMCS
 */
static void test_vmcs_addr(const char *name,
			   enum Encoding encoding,
			   u64 align,
			   bool ignored,
			   bool skip_beyond_mapped_ram,
			   u64 addr)
{
	report_prefix_pushf("%s = %lx", name, addr);
	vmcs_write(encoding, addr);
	if (skip_beyond_mapped_ram &&
	    addr > fwcfg_get_u64(FW_CFG_RAM_SIZE) - align &&
	    addr < (1ul << cpuid_maxphyaddr()))
		printf("Skipping physical address beyond mapped RAM\n");
	else if (ignored || (IS_ALIGNED(addr, align) &&
	    addr < (1ul << cpuid_maxphyaddr())))
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	report_prefix_pop();
}

/*
 * Test interesting values for a VMCS address
 */
static void test_vmcs_addr_values(const char *name,
				  enum Encoding encoding,
				  u64 align,
				  bool ignored,
				  bool skip_beyond_mapped_ram,
				  u32 bit_start, u32 bit_end)
{
	unsigned i;
	u64 orig_val = vmcs_read(encoding);

	for (i = bit_start; i <= bit_end; i++)
		test_vmcs_addr(name, encoding, align, ignored,
			       skip_beyond_mapped_ram, 1ul << i);

	test_vmcs_addr(name, encoding, align, ignored,
		       skip_beyond_mapped_ram, PAGE_SIZE - 1);
	test_vmcs_addr(name, encoding, align, ignored,
		       skip_beyond_mapped_ram, PAGE_SIZE);
	test_vmcs_addr(name, encoding, align, ignored,
		       skip_beyond_mapped_ram,
		      (1ul << cpuid_maxphyaddr()) - PAGE_SIZE);
	test_vmcs_addr(name, encoding, align, ignored,
		       skip_beyond_mapped_ram, -1ul);

	vmcs_write(encoding, orig_val);
}

/*
 * Test a physical address reference in the VMCS, when the corresponding
 * feature is enabled and when the corresponding feature is disabled.
 */
static void test_vmcs_addr_reference(u32 control_bit, enum Encoding field,
				     const char *field_name,
				     const char *control_name, u64 align,
				     bool skip_beyond_mapped_ram,
				     bool control_primary)
{
	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);
	u64 page_addr;

	if (control_primary) {
		if (!(ctrl_cpu_rev[0].clr & control_bit))
			return;
	} else {
		if (!(ctrl_cpu_rev[1].clr & control_bit))
			return;
	}

	page_addr = vmcs_read(field);

	report_prefix_pushf("%s enabled", control_name);
	if (control_primary) {
		vmcs_write(CPU_EXEC_CTRL0, primary | control_bit);
	} else {
		vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1, secondary | control_bit);
	}

	test_vmcs_addr_values(field_name, field, align, false,
			      skip_beyond_mapped_ram, 0, 63);
	report_prefix_pop();

	report_prefix_pushf("%s disabled", control_name);
	if (control_primary) {
		vmcs_write(CPU_EXEC_CTRL0, primary & ~control_bit);
	} else {
		vmcs_write(CPU_EXEC_CTRL0, primary & ~CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1, secondary & ~control_bit);
	}

	test_vmcs_addr_values(field_name, field, align, true, false, 0, 63);
	report_prefix_pop();

	vmcs_write(field, page_addr);
	vmcs_write(CPU_EXEC_CTRL0, primary);
	vmcs_write(CPU_EXEC_CTRL1, secondary);
}

/*
 * If the "use I/O bitmaps" VM-execution control is 1, bits 11:0 of
 * each I/O-bitmap address must be 0. Neither address should set any
 * bits beyond the processor's physical-address width.
 * [Intel SDM]
 */
static void test_io_bitmaps(void)
{
	test_vmcs_addr_reference(CPU_IO_BITMAP, IO_BITMAP_A,
				 "I/O bitmap A", "Use I/O bitmaps",
				 PAGE_SIZE, false, true);
	test_vmcs_addr_reference(CPU_IO_BITMAP, IO_BITMAP_B,
				 "I/O bitmap B", "Use I/O bitmaps",
				 PAGE_SIZE, false, true);
}

/*
 * If the "use MSR bitmaps" VM-execution control is 1, bits 11:0 of
 * the MSR-bitmap address must be 0. The address should not set any
 * bits beyond the processor's physical-address width.
 * [Intel SDM]
 */
static void test_msr_bitmap(void)
{
	test_vmcs_addr_reference(CPU_MSR_BITMAP, MSR_BITMAP,
				 "MSR bitmap", "Use MSR bitmaps",
				 PAGE_SIZE, false, true);
}

/*
 * If the "use TPR shadow" VM-execution control is 1, the virtual-APIC
 * address must satisfy the following checks:
 * - Bits 11:0 of the address must be 0.
 * - The address should not set any bits beyond the processor's
 *   physical-address width.
 * [Intel SDM]
 */
static void test_apic_virt_addr(void)
{
	/*
	 * Ensure the processor will never use the virtual-APIC page, since
	 * we will point it to invalid RAM.  Otherwise KVM is puzzled about
	 * what we're trying to achieve and fails vmentry.
	 */
	u32 cpu_ctrls0 = vmcs_read(CPU_EXEC_CTRL0);
	vmcs_write(CPU_EXEC_CTRL0, cpu_ctrls0 | CPU_CR8_LOAD | CPU_CR8_STORE);
	test_vmcs_addr_reference(CPU_TPR_SHADOW, APIC_VIRT_ADDR,
				 "virtual-APIC address", "Use TPR shadow",
				 PAGE_SIZE, false, true);
	vmcs_write(CPU_EXEC_CTRL0, cpu_ctrls0);
}

/*
 * If the "virtualize APIC-accesses" VM-execution control is 1, the
 * APIC-access address must satisfy the following checks:
 *  - Bits 11:0 of the address must be 0.
 *  - The address should not set any bits beyond the processor's
 *    physical-address width.
 * [Intel SDM]
 */
static void test_apic_access_addr(void)
{
	void *apic_access_page = alloc_page();

	vmcs_write(APIC_ACCS_ADDR, virt_to_phys(apic_access_page));

	test_vmcs_addr_reference(CPU_VIRT_APIC_ACCESSES, APIC_ACCS_ADDR,
				 "APIC-access address",
				 "virtualize APIC-accesses", PAGE_SIZE,
				 true, false);
}

static bool set_bit_pattern(u8 mask, u32 *secondary)
{
	u8 i;
	bool flag = false;
	u32 test_bits[3] = {
		CPU_VIRT_X2APIC,
		CPU_APIC_REG_VIRT,
		CPU_VINTD
	};

        for (i = 0; i < ARRAY_SIZE(test_bits); i++) {
		if ((mask & (1u << i)) &&
		    (ctrl_cpu_rev[1].clr & test_bits[i])) {
			*secondary |= test_bits[i];
			flag = true;
		}
	}

	return (flag);
}

/*
 * If the "use TPR shadow" VM-execution control is 0, the following
 * VM-execution controls must also be 0:
 * 	- virtualize x2APIC mode
 *	- APIC-register virtualization
 *	- virtual-interrupt delivery
 *    [Intel SDM]
 *
 * 2. If the "virtualize x2APIC mode" VM-execution control is 1, the
 *    "virtualize APIC accesses" VM-execution control must be 0.
 *    [Intel SDM]
 */
static void test_apic_virtual_ctls(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u32 primary = saved_primary;
	u32 secondary = saved_secondary;
	bool is_ctrl_valid = false;
	char str[10] = "disabled";
	u8 i = 0, j;

	/*
	 * First test
	 */
	if (!((ctrl_cpu_rev[0].clr & (CPU_SECONDARY | CPU_TPR_SHADOW)) ==
	    (CPU_SECONDARY | CPU_TPR_SHADOW)))
		return;

	primary |= CPU_SECONDARY;
	primary &= ~CPU_TPR_SHADOW;
	vmcs_write(CPU_EXEC_CTRL0, primary);

	while (1) {
		for (j = 1; j < 8; j++) {
			secondary &= ~(CPU_VIRT_X2APIC | CPU_APIC_REG_VIRT | CPU_VINTD);
			if (primary & CPU_TPR_SHADOW) {
				is_ctrl_valid = true;
			} else {
				if (! set_bit_pattern(j, &secondary))
					is_ctrl_valid = true;
				else
					is_ctrl_valid = false;
			}

			vmcs_write(CPU_EXEC_CTRL1, secondary);
			report_prefix_pushf("Use TPR shadow %s, virtualize x2APIC mode %s, APIC-register virtualization %s, virtual-interrupt delivery %s",
				str, (secondary & CPU_VIRT_X2APIC) ? "enabled" : "disabled", (secondary & CPU_APIC_REG_VIRT) ? "enabled" : "disabled", (secondary & CPU_VINTD) ? "enabled" : "disabled");
			if (is_ctrl_valid)
				test_vmx_valid_controls();
			else
				test_vmx_invalid_controls();
			report_prefix_pop();
		}

		if (i == 1)
			break;
		i++;

		primary |= CPU_TPR_SHADOW;
		vmcs_write(CPU_EXEC_CTRL0, primary);
		strcpy(str, "enabled");
	}

	/*
	 * Second test
	 */
	u32 apic_virt_ctls = (CPU_VIRT_X2APIC | CPU_VIRT_APIC_ACCESSES);

	primary = saved_primary;
	secondary = saved_secondary;
	if (!((ctrl_cpu_rev[1].clr & apic_virt_ctls) == apic_virt_ctls))
		return;

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY);
	secondary &= ~CPU_VIRT_APIC_ACCESSES;
	vmcs_write(CPU_EXEC_CTRL1, secondary & ~CPU_VIRT_X2APIC);
	report_prefix_pushf("Virtualize x2APIC mode disabled; virtualize APIC access disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary | CPU_VIRT_APIC_ACCESSES);
	report_prefix_pushf("Virtualize x2APIC mode disabled; virtualize APIC access enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary | CPU_VIRT_X2APIC);
	report_prefix_pushf("Virtualize x2APIC mode enabled; virtualize APIC access enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary & ~CPU_VIRT_APIC_ACCESSES);
	report_prefix_pushf("Virtualize x2APIC mode enabled; virtualize APIC access disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
}

/*
 * If the "virtual-interrupt delivery" VM-execution control is 1, the
 * "external-interrupt exiting" VM-execution control must be 1.
 * [Intel SDM]
 */
static void test_virtual_intr_ctls(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u32 saved_pin = vmcs_read(PIN_CONTROLS);
	u32 primary = saved_primary;
	u32 secondary = saved_secondary;
	u32 pin = saved_pin;

	if (!((ctrl_cpu_rev[1].clr & CPU_VINTD) &&
	    (ctrl_pin_rev.clr & PIN_EXTINT)))
		return;

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY | CPU_TPR_SHADOW);
	vmcs_write(CPU_EXEC_CTRL1, secondary & ~CPU_VINTD);
	vmcs_write(PIN_CONTROLS, pin & ~PIN_EXTINT);
	report_prefix_pushf("Virtualize interrupt-delivery disabled; external-interrupt exiting disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary | CPU_VINTD);
	report_prefix_pushf("Virtualize interrupt-delivery enabled; external-interrupt exiting disabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, pin | PIN_EXTINT);
	report_prefix_pushf("Virtualize interrupt-delivery enabled; external-interrupt exiting enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, pin & ~PIN_EXTINT);
	report_prefix_pushf("Virtualize interrupt-delivery enabled; external-interrupt exiting disabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
	vmcs_write(PIN_CONTROLS, saved_pin);
}

static void test_pi_desc_addr(u64 addr, bool is_ctrl_valid)
{
	vmcs_write(POSTED_INTR_DESC_ADDR, addr);
	report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-descriptor-address 0x%lx", addr);
	if (is_ctrl_valid)
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	report_prefix_pop();
}

/*
 * If the "process posted interrupts" VM-execution control is 1, the
 * following must be true:
 *
 *	- The "virtual-interrupt delivery" VM-execution control is 1.
 *	- The "acknowledge interrupt on exit" VM-exit control is 1.
 *	- The posted-interrupt notification vector has a value in the
 *	- range 0 - 255 (bits 15:8 are all 0).
 *	- Bits 5:0 of the posted-interrupt descriptor address are all 0.
 *	- The posted-interrupt descriptor address does not set any bits
 *	  beyond the processor's physical-address width.
 * [Intel SDM]
 */
static void test_posted_intr(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u32 saved_pin = vmcs_read(PIN_CONTROLS);
	u32 exit_ctl_saved = vmcs_read(EXI_CONTROLS);
	u32 primary = saved_primary;
	u32 secondary = saved_secondary;
	u32 pin = saved_pin;
	u32 exit_ctl = exit_ctl_saved;
	u16 vec;
	int i;

	if (!((ctrl_pin_rev.clr & PIN_POST_INTR) &&
	    (ctrl_cpu_rev[1].clr & CPU_VINTD) &&
	    (ctrl_exit_rev.clr & EXI_INTA)))
		return;

	vmcs_write(CPU_EXEC_CTRL0, primary | CPU_SECONDARY | CPU_TPR_SHADOW);

	/*
	 * Test virtual-interrupt-delivery and acknowledge-interrupt-on-exit
	 */
	pin |= PIN_POST_INTR;
	vmcs_write(PIN_CONTROLS, pin);
	secondary &= ~CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery disabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	secondary |= CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	exit_ctl &= ~EXI_INTA;
	vmcs_write(EXI_CONTROLS, exit_ctl);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled; acknowledge-interrupt-on-exit disabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	exit_ctl |= EXI_INTA;
	vmcs_write(EXI_CONTROLS, exit_ctl);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled; acknowledge-interrupt-on-exit enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	secondary &= ~CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery disabled; acknowledge-interrupt-on-exit enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	secondary |= CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Process-posted-interrupts enabled; virtual-interrupt-delivery enabled; acknowledge-interrupt-on-exit enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	/*
	 * Test posted-interrupt notification vector
	 */
	for (i = 0; i < 8; i++) {
		vec = (1ul << i);
		vmcs_write(PINV, vec);
		report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-notification-vector %u", vec);
		test_vmx_valid_controls();
		report_prefix_pop();
	}
	for (i = 8; i < 16; i++) {
		vec = (1ul << i);
		vmcs_write(PINV, vec);
		report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-notification-vector %u", vec);
		test_vmx_invalid_controls();
		report_prefix_pop();
	}

	vec &= ~(0xff << 8);
	vmcs_write(PINV, vec);
	report_prefix_pushf("Process-posted-interrupts enabled; posted-interrupt-notification-vector %u", vec);
	test_vmx_valid_controls();
	report_prefix_pop();

	/*
	 * Test posted-interrupt descriptor address
	 */
	for (i = 0; i < 6; i++) {
		test_pi_desc_addr(1ul << i, false);
	}

	test_pi_desc_addr(0xf0, false);
	test_pi_desc_addr(0xff, false);
	test_pi_desc_addr(0x0f, false);
	test_pi_desc_addr(0x8000, true);
	test_pi_desc_addr(0x00, true);
	test_pi_desc_addr(0xc000, true);

	test_vmcs_addr_values("process-posted interrupts",
			       POSTED_INTR_DESC_ADDR, 64,
			       false, false, 0, 63);

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
	vmcs_write(PIN_CONTROLS, saved_pin);
}

static void test_apic_ctls(void)
{
	test_apic_virt_addr();
	test_apic_access_addr();
	test_apic_virtual_ctls();
	test_virtual_intr_ctls();
	test_posted_intr();
}

/*
 * If the "enable VPID" VM-execution control is 1, the value of the
 * of the VPID VM-execution control field must not be 0000H.
 * [Intel SDM]
 */
static void test_vpid(void)
{
	u32 saved_primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 saved_secondary = vmcs_read(CPU_EXEC_CTRL1);
	u16 vpid = 0x0000;
	int i;

	if (!is_vpid_supported()) {
		report_skip("%s : Secondary controls and/or VPID not supported", __func__);
		return;
	}

	vmcs_write(CPU_EXEC_CTRL0, saved_primary | CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary & ~CPU_VPID);
	vmcs_write(VPID, vpid);
	report_prefix_pushf("VPID disabled; VPID value %x", vpid);
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, saved_secondary | CPU_VPID);
	report_prefix_pushf("VPID enabled; VPID value %x", vpid);
	test_vmx_invalid_controls();
	report_prefix_pop();

	for (i = 0; i < 16; i++) {
		vpid = (short)1 << i;;
		vmcs_write(VPID, vpid);
		report_prefix_pushf("VPID enabled; VPID value %x", vpid);
		test_vmx_valid_controls();
		report_prefix_pop();
	}

	vmcs_write(CPU_EXEC_CTRL0, saved_primary);
	vmcs_write(CPU_EXEC_CTRL1, saved_secondary);
}

static void set_vtpr(unsigned vtpr)
{
	*(u32 *)phys_to_virt(vmcs_read(APIC_VIRT_ADDR) + APIC_TASKPRI) = vtpr;
}

static void try_tpr_threshold_and_vtpr(unsigned threshold, unsigned vtpr)
{
	bool valid = true;
	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);

	if ((primary & CPU_TPR_SHADOW) &&
	    (!(primary & CPU_SECONDARY) ||
	     !(secondary & (CPU_VINTD | CPU_VIRT_APIC_ACCESSES))))
		valid = (threshold & 0xf) <= ((vtpr >> 4) & 0xf);

	set_vtpr(vtpr);
	report_prefix_pushf("TPR threshold 0x%x, VTPR.class 0x%x",
	    threshold, (vtpr >> 4) & 0xf);
	if (valid)
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	report_prefix_pop();
}

static void test_invalid_event_injection(void)
{
	u32 ent_intr_info_save = vmcs_read(ENT_INTR_INFO);
	u32 ent_intr_error_save = vmcs_read(ENT_INTR_ERROR);
	u32 ent_inst_len_save = vmcs_read(ENT_INST_LEN);
	u32 primary_save = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary_save = vmcs_read(CPU_EXEC_CTRL1);
	u64 guest_cr0_save = vmcs_read(GUEST_CR0);
	u32 ent_intr_info_base = INTR_INFO_VALID_MASK;
	u32 ent_intr_info, ent_intr_err, ent_intr_len;
	u32 cnt;

	/* Setup */
	report_prefix_push("invalid event injection");
	vmcs_write(ENT_INTR_ERROR, 0x00000000);
	vmcs_write(ENT_INST_LEN, 0x00000001);

	/* The field's interruption type is not set to a reserved value. */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_RESERVED | DE_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "RESERVED interruption type invalid [-]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_TYPE_EXT_INTR |
			DE_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "RESERVED interruption type invalid [+]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_valid_controls();
	report_prefix_pop();

	/* If the interruption type is other event, the vector is 0. */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_OTHER_EVENT | DB_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(OTHER EVENT && vector != 0) invalid [-]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	/* If the interruption type is NMI, the vector is 2 (negative case). */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_NMI_INTR | DE_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(NMI && vector != 2) invalid [-]", ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	/* If the interruption type is NMI, the vector is 2 (positive case). */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_NMI_INTR | NMI_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(NMI && vector == 2) valid [+]", ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_valid_controls();
	report_prefix_pop();

	/*
	 * If the interruption type
	 * is HW exception, the vector is at most 31.
	 */
	ent_intr_info = ent_intr_info_base | INTR_TYPE_HARD_EXCEPTION | 0x20;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "(HW exception && vector > 31) invalid [-]",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	/*
	 * deliver-error-code is 1 iff either
	 * (a) the "unrestricted guest" VM-execution control is 0
	 * (b) CR0.PE is set.
	 */

	/* Assert that unrestricted guest is disabled or unsupported */
	assert(!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
	       !(secondary_save & CPU_URG));

	ent_intr_info = ent_intr_info_base | INTR_TYPE_HARD_EXCEPTION |
			GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [-]",
			    ent_intr_info);
	vmcs_write(GUEST_CR0, guest_cr0_save & ~X86_CR0_PE & ~X86_CR0_PG);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_INFO_DELIVER_CODE_MASK |
			INTR_TYPE_HARD_EXCEPTION | GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [+]",
			    ent_intr_info);
	vmcs_write(GUEST_CR0, guest_cr0_save & ~X86_CR0_PE & ~X86_CR0_PG);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_valid_controls();
	report_prefix_pop();

	if (enable_unrestricted_guest(false))
		goto skip_unrestricted_guest;

	ent_intr_info = ent_intr_info_base | INTR_INFO_DELIVER_CODE_MASK |
			INTR_TYPE_HARD_EXCEPTION | GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [-]",
			    ent_intr_info);
	vmcs_write(GUEST_CR0, guest_cr0_save & ~X86_CR0_PE & ~X86_CR0_PG);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	ent_intr_info = ent_intr_info_base | INTR_TYPE_HARD_EXCEPTION |
			GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "error code <-> (!URG || prot_mode) [-]",
			    ent_intr_info);
	vmcs_write(GUEST_CR0, guest_cr0_save | X86_CR0_PE);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	test_vmx_invalid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL1, secondary_save);
	vmcs_write(CPU_EXEC_CTRL0, primary_save);

skip_unrestricted_guest:
	vmcs_write(GUEST_CR0, guest_cr0_save);

	/* deliver-error-code is 1 iff the interruption type is HW exception */
	report_prefix_push("error code <-> HW exception");
	for (cnt = 0; cnt < 8; cnt++) {
		u32 exception_type_mask = cnt << 8;
		u32 deliver_error_code_mask =
			exception_type_mask != INTR_TYPE_HARD_EXCEPTION ?
			INTR_INFO_DELIVER_CODE_MASK : 0;

		ent_intr_info = ent_intr_info_base | deliver_error_code_mask |
				exception_type_mask | GP_VECTOR;
		report_prefix_pushf("VM-entry intr info=0x%x [-]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_invalid_controls();
		report_prefix_pop();
	}
	report_prefix_pop();

	/*
	 * deliver-error-code is 1 iff the the vector
	 * indicates an exception that would normally deliver an error code
	 */
	report_prefix_push("error code <-> vector delivers error code");
	for (cnt = 0; cnt < 32; cnt++) {
		bool has_error_code = false;
		u32 deliver_error_code_mask;

		switch (cnt) {
		case DF_VECTOR:
		case TS_VECTOR:
		case NP_VECTOR:
		case SS_VECTOR:
		case GP_VECTOR:
		case PF_VECTOR:
		case AC_VECTOR:
			has_error_code = true;
		case CP_VECTOR:
			/* Some CPUs have error code and some do not, skip */
			continue;
		}

		/* Negative case */
		deliver_error_code_mask = has_error_code ?
						0 :
						INTR_INFO_DELIVER_CODE_MASK;
		ent_intr_info = ent_intr_info_base | deliver_error_code_mask |
				INTR_TYPE_HARD_EXCEPTION | cnt;
		report_prefix_pushf("VM-entry intr info=0x%x [-]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_invalid_controls();
		report_prefix_pop();

		/* Positive case */
		deliver_error_code_mask = has_error_code ?
						INTR_INFO_DELIVER_CODE_MASK :
						0;
		ent_intr_info = ent_intr_info_base | deliver_error_code_mask |
				INTR_TYPE_HARD_EXCEPTION | cnt;
		report_prefix_pushf("VM-entry intr info=0x%x [+]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_valid_controls();
		report_prefix_pop();
	}
	report_prefix_pop();

	/* Reserved bits in the field (30:12) are 0. */
	report_prefix_push("reserved bits clear");
	for (cnt = 12; cnt <= 30; cnt++) {
		ent_intr_info = ent_intr_info_base |
				INTR_INFO_DELIVER_CODE_MASK |
				INTR_TYPE_HARD_EXCEPTION | GP_VECTOR |
				(1U << cnt);
		report_prefix_pushf("VM-entry intr info=0x%x [-]",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);
		test_vmx_invalid_controls();
		report_prefix_pop();
	}
	report_prefix_pop();

	/*
	 * If deliver-error-code is 1
	 * bits 31:16 of the VM-entry exception error-code field are 0.
	 */
	ent_intr_info = ent_intr_info_base | INTR_INFO_DELIVER_CODE_MASK |
			INTR_TYPE_HARD_EXCEPTION | GP_VECTOR;
	report_prefix_pushf("%s, VM-entry intr info=0x%x",
			    "VM-entry exception error code[31:16] clear",
			    ent_intr_info);
	vmcs_write(ENT_INTR_INFO, ent_intr_info);
	for (cnt = 16; cnt <= 31; cnt++) {
		ent_intr_err = 1U << cnt;
		report_prefix_pushf("VM-entry intr error=0x%x [-]",
				    ent_intr_err);
		vmcs_write(ENT_INTR_ERROR, ent_intr_err);
		test_vmx_invalid_controls();
		report_prefix_pop();
	}
	vmcs_write(ENT_INTR_ERROR, 0x00000000);
	report_prefix_pop();

	/*
	 * If the interruption type is software interrupt, software exception,
	 * or privileged software exception, the VM-entry instruction-length
	 * field is in the range 0 - 15.
	 */

	for (cnt = 0; cnt < 3; cnt++) {
		switch (cnt) {
		case 0:
			ent_intr_info = ent_intr_info_base |
					INTR_TYPE_SOFT_INTR;
			break;
		case 1:
			ent_intr_info = ent_intr_info_base |
					INTR_TYPE_SOFT_EXCEPTION;
			break;
		case 2:
			ent_intr_info = ent_intr_info_base |
					INTR_TYPE_PRIV_SW_EXCEPTION;
			break;
		}
		report_prefix_pushf("%s, VM-entry intr info=0x%x",
				    "VM-entry instruction-length check",
				    ent_intr_info);
		vmcs_write(ENT_INTR_INFO, ent_intr_info);

		/* Instruction length set to -1 (0xFFFFFFFF) should fail */
		ent_intr_len = -1;
		report_prefix_pushf("VM-entry intr length = 0x%x [-]",
				    ent_intr_len);
		vmcs_write(ENT_INST_LEN, ent_intr_len);
		test_vmx_invalid_controls();
		report_prefix_pop();

		/* Instruction length set to 16 should fail */
		ent_intr_len = 0x00000010;
		report_prefix_pushf("VM-entry intr length = 0x%x [-]",
				    ent_intr_len);
		vmcs_write(ENT_INST_LEN, 0x00000010);
		test_vmx_invalid_controls();
		report_prefix_pop();

		report_prefix_pop();
	}

	/* Cleanup */
	vmcs_write(ENT_INTR_INFO, ent_intr_info_save);
	vmcs_write(ENT_INTR_ERROR, ent_intr_error_save);
	vmcs_write(ENT_INST_LEN, ent_inst_len_save);
	vmcs_write(CPU_EXEC_CTRL0, primary_save);
	vmcs_write(CPU_EXEC_CTRL1, secondary_save);
	vmcs_write(GUEST_CR0, guest_cr0_save);
	report_prefix_pop();
}

/*
 * Test interesting vTPR values for a given TPR threshold.
 */
static void test_vtpr_values(unsigned threshold)
{
	try_tpr_threshold_and_vtpr(threshold, (threshold - 1) << 4);
	try_tpr_threshold_and_vtpr(threshold, threshold << 4);
	try_tpr_threshold_and_vtpr(threshold, (threshold + 1) << 4);
}

static void try_tpr_threshold(unsigned threshold)
{
	bool valid = true;

	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);

	if ((primary & CPU_TPR_SHADOW) && !((primary & CPU_SECONDARY) &&
	    (secondary & CPU_VINTD)))
		valid = !(threshold >> 4);

	set_vtpr(-1);
	vmcs_write(TPR_THRESHOLD, threshold);
	report_prefix_pushf("TPR threshold 0x%x, VTPR.class 0xf", threshold);
	if (valid)
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	report_prefix_pop();

	if (valid)
		test_vtpr_values(threshold);
}

/*
 * Test interesting TPR threshold values.
 */
static void test_tpr_threshold_values(void)
{
	unsigned i;

	for (i = 0; i < 0x10; i++)
		try_tpr_threshold(i);
	for (i = 4; i < 32; i++)
		try_tpr_threshold(1u << i);
	try_tpr_threshold(-1u);
	try_tpr_threshold(0x7fffffff);
}

/*
 * This test covers the following two VM entry checks:
 *
 *      i) If the "use TPR shadow" VM-execution control is 1 and the
 *         "virtual-interrupt delivery" VM-execution control is 0, bits
 *         31:4 of the TPR threshold VM-execution control field must
	   be 0.
 *         [Intel SDM]
 *
 *      ii) If the "use TPR shadow" VM-execution control is 1, the
 *          "virtual-interrupt delivery" VM-execution control is 0
 *          and the "virtualize APIC accesses" VM-execution control
 *          is 0, the value of bits 3:0 of the TPR threshold VM-execution
 *          control field must not be greater than the value of bits
 *          7:4 of VTPR.
 *          [Intel SDM]
 */
static void test_tpr_threshold(void)
{
	u32 primary = vmcs_read(CPU_EXEC_CTRL0);
	u64 apic_virt_addr = vmcs_read(APIC_VIRT_ADDR);
	u64 threshold = vmcs_read(TPR_THRESHOLD);
	void *virtual_apic_page;

	if (!(ctrl_cpu_rev[0].clr & CPU_TPR_SHADOW))
		return;

	virtual_apic_page = alloc_page();
	memset(virtual_apic_page, 0xff, PAGE_SIZE);
	vmcs_write(APIC_VIRT_ADDR, virt_to_phys(virtual_apic_page));

	vmcs_write(CPU_EXEC_CTRL0, primary & ~(CPU_TPR_SHADOW | CPU_SECONDARY));
	report_prefix_pushf("Use TPR shadow disabled, secondary controls disabled");
	test_tpr_threshold_values();
	report_prefix_pop();
	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | CPU_TPR_SHADOW);
	report_prefix_pushf("Use TPR shadow enabled, secondary controls disabled");
	test_tpr_threshold_values();
	report_prefix_pop();

	if (!((ctrl_cpu_rev[0].clr & CPU_SECONDARY) &&
	    (ctrl_cpu_rev[1].clr & (CPU_VINTD  | CPU_VIRT_APIC_ACCESSES))))
		goto out;
	u32 secondary = vmcs_read(CPU_EXEC_CTRL1);

	if (ctrl_cpu_rev[1].clr & CPU_VINTD) {
		vmcs_write(CPU_EXEC_CTRL1, CPU_VINTD);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls disabled; virtual-interrupt delivery enabled; virtualize APIC accesses disabled");
		test_tpr_threshold_values();
		report_prefix_pop();

		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls enabled; virtual-interrupt delivery enabled; virtualize APIC accesses disabled");
		test_tpr_threshold_values();
		report_prefix_pop();
	}

	if (ctrl_cpu_rev[1].clr & CPU_VIRT_APIC_ACCESSES) {
		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) & ~CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1, CPU_VIRT_APIC_ACCESSES);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls disabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();

		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls enabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();
	}

	if ((ctrl_cpu_rev[1].clr &
	     (CPU_VINTD | CPU_VIRT_APIC_ACCESSES)) ==
	    (CPU_VINTD | CPU_VIRT_APIC_ACCESSES)) {
		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) & ~CPU_SECONDARY);
		vmcs_write(CPU_EXEC_CTRL1,
			   CPU_VINTD | CPU_VIRT_APIC_ACCESSES);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls disabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();

		vmcs_write(CPU_EXEC_CTRL0,
			   vmcs_read(CPU_EXEC_CTRL0) | CPU_SECONDARY);
		report_prefix_pushf("Use TPR shadow enabled; secondary controls enabled; virtual-interrupt delivery enabled; virtualize APIC accesses enabled");
		test_tpr_threshold_values();
		report_prefix_pop();
	}

	vmcs_write(CPU_EXEC_CTRL1, secondary);
out:
	vmcs_write(TPR_THRESHOLD, threshold);
	vmcs_write(APIC_VIRT_ADDR, apic_virt_addr);
	vmcs_write(CPU_EXEC_CTRL0, primary);
}

/*
 * This test verifies the following two vmentry checks:
 *
 *  If the "NMI exiting" VM-execution control is 0, "Virtual NMIs"
 *  VM-execution control must be 0.
 *  [Intel SDM]
 *
 *  If the "virtual NMIs" VM-execution control is 0, the "NMI-window
 *  exiting" VM-execution control must be 0.
 *  [Intel SDM]
 */
static void test_nmi_ctrls(void)
{
	u32 pin_ctrls, cpu_ctrls0, test_pin_ctrls, test_cpu_ctrls0;

	if ((ctrl_pin_rev.clr & (PIN_NMI | PIN_VIRT_NMI)) !=
	    (PIN_NMI | PIN_VIRT_NMI)) {
		report_skip("%s : NMI exiting and/or Virtual NMIs not supported", __func__);
		return;
	}

	/* Save the controls so that we can restore them after our tests */
	pin_ctrls = vmcs_read(PIN_CONTROLS);
	cpu_ctrls0 = vmcs_read(CPU_EXEC_CTRL0);

	test_pin_ctrls = pin_ctrls & ~(PIN_NMI | PIN_VIRT_NMI);
	test_cpu_ctrls0 = cpu_ctrls0 & ~CPU_NMI_WINDOW;

	vmcs_write(PIN_CONTROLS, test_pin_ctrls);
	report_prefix_pushf("NMI-exiting disabled, virtual-NMIs disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | PIN_VIRT_NMI);
	report_prefix_pushf("NMI-exiting disabled, virtual-NMIs enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | (PIN_NMI | PIN_VIRT_NMI));
	report_prefix_pushf("NMI-exiting enabled, virtual-NMIs enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | PIN_NMI);
	report_prefix_pushf("NMI-exiting enabled, virtual-NMIs disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	if (!(ctrl_cpu_rev[0].clr & CPU_NMI_WINDOW)) {
		report_info("NMI-window exiting is not supported, skipping...");
		goto done;
	}

	vmcs_write(PIN_CONTROLS, test_pin_ctrls);
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0 | CPU_NMI_WINDOW);
	report_prefix_pushf("Virtual-NMIs disabled, NMI-window-exiting enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls);
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0);
	report_prefix_pushf("Virtual-NMIs disabled, NMI-window-exiting disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | (PIN_NMI | PIN_VIRT_NMI));
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0 | CPU_NMI_WINDOW);
	report_prefix_pushf("Virtual-NMIs enabled, NMI-window-exiting enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, test_pin_ctrls | (PIN_NMI | PIN_VIRT_NMI));
	vmcs_write(CPU_EXEC_CTRL0, test_cpu_ctrls0);
	report_prefix_pushf("Virtual-NMIs enabled, NMI-window-exiting disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	/* Restore the controls to their original values */
	vmcs_write(CPU_EXEC_CTRL0, cpu_ctrls0);
done:
	vmcs_write(PIN_CONTROLS, pin_ctrls);
}

static void test_eptp_ad_bit(u64 eptp, bool is_ctrl_valid)
{
	vmcs_write(EPTP, eptp);
	report_prefix_pushf("Enable-EPT enabled; EPT accessed and dirty flag %s",
	    (eptp & EPTP_AD_FLAG) ? "1": "0");
	if (is_ctrl_valid)
		test_vmx_valid_controls();
	else
		test_vmx_invalid_controls();
	report_prefix_pop();

}

/*
 * 1. If the "enable EPT" VM-execution control is 1, the "EPTP VM-execution"
 *    control field must satisfy the following checks:
 *
 *     - The EPT memory type (bits 2:0) must be a value supported by the
 *	 processor as indicated in the IA32_VMX_EPT_VPID_CAP MSR.
 *     - Bits 5:3 (1 less than the EPT page-walk length) must indicate a
 *	 supported EPT page-walk length.
 *     - Bit 6 (enable bit for accessed and dirty flags for EPT) must be
 *	 0 if bit 21 of the IA32_VMX_EPT_VPID_CAP MSR is read as 0,
 *	 indicating that the processor does not support accessed and dirty
 *	 dirty flags for EPT.
 *     - Reserved bits 11:7 and 63:N (where N is the processor's
 *	 physical-address width) must all be 0.
 *
 * 2. If the "unrestricted guest" VM-execution control is 1, the
 *    "enable EPT" VM-execution control must also be 1.
 */
static void test_ept_eptp(void)
{
	u32 primary_saved = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary_saved = vmcs_read(CPU_EXEC_CTRL1);
	u64 eptp_saved = vmcs_read(EPTP);
	u32 primary = primary_saved;
	u32 secondary = secondary_saved;
	u64 eptp = eptp_saved;
	u32 i, maxphysaddr;
	u64 j, resv_bits_mask = 0;

	if (!((ctrl_cpu_rev[0].clr & CPU_SECONDARY) &&
	    (ctrl_cpu_rev[1].clr & CPU_EPT))) {
		report_skip("%s : \"CPU secondary\" and/or \"enable EPT\" exec control not supported", __func__);
		return;
	}

	/* Support for 4-level EPT is mandatory. */
	report(is_4_level_ept_supported(), "4-level EPT support check");

	primary |= CPU_SECONDARY;
	vmcs_write(CPU_EXEC_CTRL0, primary);
	secondary |= CPU_EPT;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	eptp = (eptp & ~EPTP_PG_WALK_LEN_MASK) |
	    (3ul << EPTP_PG_WALK_LEN_SHIFT);
	vmcs_write(EPTP, eptp);

	for (i = 0; i < 8; i++) {
		eptp = (eptp & ~EPT_MEM_TYPE_MASK) | i;
		vmcs_write(EPTP, eptp);
		report_prefix_pushf("Enable-EPT enabled; EPT memory type %lu",
		    eptp & EPT_MEM_TYPE_MASK);
		if (is_ept_memtype_supported(i))
			test_vmx_valid_controls();
		else
			test_vmx_invalid_controls();
		report_prefix_pop();
	}

	eptp = (eptp & ~EPT_MEM_TYPE_MASK) | 6ul;

	/*
	 * Page walk length (bits 5:3).  Note, the value in VMCS.EPTP "is 1
	 * less than the EPT page-walk length".
	 */
	for (i = 0; i < 8; i++) {
		eptp = (eptp & ~EPTP_PG_WALK_LEN_MASK) |
		    (i << EPTP_PG_WALK_LEN_SHIFT);

		vmcs_write(EPTP, eptp);
		report_prefix_pushf("Enable-EPT enabled; EPT page walk length %lu",
		    eptp & EPTP_PG_WALK_LEN_MASK);
		if (i == 3 || (i == 4 && is_5_level_ept_supported()))
			test_vmx_valid_controls();
		else
			test_vmx_invalid_controls();
		report_prefix_pop();
	}

	eptp = (eptp & ~EPTP_PG_WALK_LEN_MASK) |
	    3ul << EPTP_PG_WALK_LEN_SHIFT;

	/*
	 * Accessed and dirty flag (bit 6)
	 */
	if (ept_ad_bits_supported()) {
		report_info("Processor supports accessed and dirty flag");
		eptp &= ~EPTP_AD_FLAG;
		test_eptp_ad_bit(eptp, true);

		eptp |= EPTP_AD_FLAG;
		test_eptp_ad_bit(eptp, true);
	} else {
		report_info("Processor does not supports accessed and dirty flag");
		eptp &= ~EPTP_AD_FLAG;
		test_eptp_ad_bit(eptp, true);

		eptp |= EPTP_AD_FLAG;
		test_eptp_ad_bit(eptp, false);
	}

	/*
	 * Reserved bits [11:7] and [63:N]
	 */
	for (i = 0; i < 32; i++) {
		eptp = (eptp &
		    ~(EPTP_RESERV_BITS_MASK << EPTP_RESERV_BITS_SHIFT)) |
		    (i << EPTP_RESERV_BITS_SHIFT);
		vmcs_write(EPTP, eptp);
		report_prefix_pushf("Enable-EPT enabled; reserved bits [11:7] %lu",
		    (eptp >> EPTP_RESERV_BITS_SHIFT) &
		    EPTP_RESERV_BITS_MASK);
		if (i == 0)
			test_vmx_valid_controls();
		else
			test_vmx_invalid_controls();
		report_prefix_pop();
	}

	eptp = (eptp & ~(EPTP_RESERV_BITS_MASK << EPTP_RESERV_BITS_SHIFT));

	maxphysaddr = cpuid_maxphyaddr();
	for (i = 0; i < (63 - maxphysaddr + 1); i++) {
		resv_bits_mask |= 1ul << i;
	}

	for (j = maxphysaddr - 1; j <= 63; j++) {
		eptp = (eptp & ~(resv_bits_mask << maxphysaddr)) |
		    (j < maxphysaddr ? 0 : 1ul << j);
		vmcs_write(EPTP, eptp);
		report_prefix_pushf("Enable-EPT enabled; reserved bits [63:N] %lu",
		    (eptp >> maxphysaddr) & resv_bits_mask);
		if (j < maxphysaddr)
			test_vmx_valid_controls();
		else
			test_vmx_invalid_controls();
		report_prefix_pop();
	}

	secondary &= ~(CPU_EPT | CPU_URG);
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Enable-EPT disabled, unrestricted-guest disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	if (!(ctrl_cpu_rev[1].clr & CPU_URG))
		goto skip_unrestricted_guest;

	secondary |= CPU_URG;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Enable-EPT disabled, unrestricted-guest enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	secondary |= CPU_EPT;
	setup_dummy_ept();
	report_prefix_pushf("Enable-EPT enabled, unrestricted-guest enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

skip_unrestricted_guest:
	secondary &= ~CPU_URG;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("Enable-EPT enabled, unrestricted-guest disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(CPU_EXEC_CTRL0, primary_saved);
	vmcs_write(CPU_EXEC_CTRL1, secondary_saved);
	vmcs_write(EPTP, eptp_saved);
}

/*
 * If the 'enable PML' VM-execution control is 1, the 'enable EPT'
 * VM-execution control must also be 1. In addition, the PML address
 * must satisfy the following checks:
 *
 *    * Bits 11:0 of the address must be 0.
 *    * The address should not set any bits beyond the processor's
 *	physical-address width.
 *
 *  [Intel SDM]
 */
static void test_pml(void)
{
	u32 primary_saved = vmcs_read(CPU_EXEC_CTRL0);
	u32 secondary_saved = vmcs_read(CPU_EXEC_CTRL1);
	u32 primary = primary_saved;
	u32 secondary = secondary_saved;

	if (!((ctrl_cpu_rev[0].clr & CPU_SECONDARY) &&
	    (ctrl_cpu_rev[1].clr & CPU_EPT) && (ctrl_cpu_rev[1].clr & CPU_PML))) {
		report_skip("%s : \"Secondary execution\" or \"enable EPT\" or \"enable PML\" control not supported", __func__);
		return;
	}

	primary |= CPU_SECONDARY;
	vmcs_write(CPU_EXEC_CTRL0, primary);
	secondary &= ~(CPU_PML | CPU_EPT);
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("enable-PML disabled, enable-EPT disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	secondary |= CPU_PML;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("enable-PML enabled, enable-EPT disabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	secondary |= CPU_EPT;
	setup_dummy_ept();
	report_prefix_pushf("enable-PML enabled, enable-EPT enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	secondary &= ~CPU_PML;
	vmcs_write(CPU_EXEC_CTRL1, secondary);
	report_prefix_pushf("enable-PML disabled, enable EPT enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	test_vmcs_addr_reference(CPU_PML, PMLADDR, "PML address", "PML",
				 PAGE_SIZE, false, false);

	vmcs_write(CPU_EXEC_CTRL0, primary_saved);
	vmcs_write(CPU_EXEC_CTRL1, secondary_saved);
}

 /*
 * If the "activate VMX-preemption timer" VM-execution control is 0, the
 * the "save VMX-preemption timer value" VM-exit control must also be 0.
 *
 *  [Intel SDM]
 */
static void test_vmx_preemption_timer(void)
{
	u32 saved_pin = vmcs_read(PIN_CONTROLS);
	u32 saved_exit = vmcs_read(EXI_CONTROLS);
	u32 pin = saved_pin;
	u32 exit = saved_exit;

	if (!((ctrl_exit_rev.clr & EXI_SAVE_PREEMPT) ||
	    (ctrl_pin_rev.clr & PIN_PREEMPT))) {
		report_skip("%s : \"Save-VMX-preemption-timer\" and/or \"Enable-VMX-preemption-timer\" control not supported", __func__);
		return;
	}

	pin |= PIN_PREEMPT;
	vmcs_write(PIN_CONTROLS, pin);
	exit &= ~EXI_SAVE_PREEMPT;
	vmcs_write(EXI_CONTROLS, exit);
	report_prefix_pushf("enable-VMX-preemption-timer enabled, save-VMX-preemption-timer disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	exit |= EXI_SAVE_PREEMPT;
	vmcs_write(EXI_CONTROLS, exit);
	report_prefix_pushf("enable-VMX-preemption-timer enabled, save-VMX-preemption-timer enabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	pin &= ~PIN_PREEMPT;
	vmcs_write(PIN_CONTROLS, pin);
	report_prefix_pushf("enable-VMX-preemption-timer disabled, save-VMX-preemption-timer enabled");
	test_vmx_invalid_controls();
	report_prefix_pop();

	exit &= ~EXI_SAVE_PREEMPT;
	vmcs_write(EXI_CONTROLS, exit);
	report_prefix_pushf("enable-VMX-preemption-timer disabled, save-VMX-preemption-timer disabled");
	test_vmx_valid_controls();
	report_prefix_pop();

	vmcs_write(PIN_CONTROLS, saved_pin);
	vmcs_write(EXI_CONTROLS, saved_exit);
}

extern unsigned char test_mtf1;
extern unsigned char test_mtf2;
extern unsigned char test_mtf3;
extern unsigned char test_mtf4;

static void test_mtf_guest(void)
{
	asm ("vmcall;\n\t"
	     "out %al, $0x80;\n\t"
	     "test_mtf1:\n\t"
	     "vmcall;\n\t"
	     "out %al, $0x80;\n\t"
	     "test_mtf2:\n\t"
	     /*
	      * Prepare for the 'MOV CR3' test. Attempt to induce a
	      * general-protection fault by moving a non-canonical address into
	      * CR3. The 'MOV CR3' instruction does not take an imm64 operand,
	      * so we must MOV the desired value into a register first.
	      *
	      * MOV RAX is done before the VMCALL such that MTF is only enabled
	      * for the instruction under test.
	      */
	     "mov $0xaaaaaaaaaaaaaaaa, %rax;\n\t"
	     "vmcall;\n\t"
	     "mov %rax, %cr3;\n\t"
	     "test_mtf3:\n\t"
	     "vmcall;\n\t"
	     /*
	      * ICEBP/INT1 instruction. Though the instruction is now
	      * documented, don't rely on assemblers enumerating the
	      * instruction. Resort to hand assembly.
	      */
	     ".byte 0xf1;\n\t"
	     "vmcall;\n\t"
	     "test_mtf4:\n\t"
	     "mov $0, %eax;\n\t");
}

static void test_mtf_gp_handler(struct ex_regs *regs)
{
	regs->rip = (unsigned long) &test_mtf3;
}

static void test_mtf_db_handler(struct ex_regs *regs)
{
}

static void enable_mtf(void)
{
	u32 ctrl0 = vmcs_read(CPU_EXEC_CTRL0);

	vmcs_write(CPU_EXEC_CTRL0, ctrl0 | CPU_MTF);
}

static void disable_mtf(void)
{
	u32 ctrl0 = vmcs_read(CPU_EXEC_CTRL0);

	vmcs_write(CPU_EXEC_CTRL0, ctrl0 & ~CPU_MTF);
}

static void enable_tf(void)
{
	unsigned long rflags = vmcs_read(GUEST_RFLAGS);

	vmcs_write(GUEST_RFLAGS, rflags | X86_EFLAGS_TF);
}

static void disable_tf(void)
{
	unsigned long rflags = vmcs_read(GUEST_RFLAGS);

	vmcs_write(GUEST_RFLAGS, rflags & ~X86_EFLAGS_TF);
}

static void report_mtf(const char *insn_name, unsigned long exp_rip)
{
	unsigned long rip = vmcs_read(GUEST_RIP);

	assert_exit_reason(VMX_MTF);
	report(rip == exp_rip, "MTF VM-exit after %s. RIP: 0x%lx (expected 0x%lx)",
	       insn_name, rip, exp_rip);
}

static void vmx_mtf_test(void)
{
	unsigned long pending_dbg;
	handler old_gp, old_db;

	if (!(ctrl_cpu_rev[0].clr & CPU_MTF)) {
		report_skip("%s : \"Monitor trap flag\" exec control not supported", __func__);
		return;
	}

	test_set_guest(test_mtf_guest);

	/* Expect an MTF VM-exit after OUT instruction */
	enter_guest();
	skip_exit_vmcall();

	enable_mtf();
	enter_guest();
	report_mtf("OUT", (unsigned long) &test_mtf1);
	disable_mtf();

	/*
	 * Concurrent #DB trap and MTF on instruction boundary. Expect MTF
	 * VM-exit with populated 'pending debug exceptions' VMCS field.
	 */
	enter_guest();
	skip_exit_vmcall();

	enable_mtf();
	enable_tf();

	enter_guest();
	report_mtf("OUT", (unsigned long) &test_mtf2);
	pending_dbg = vmcs_read(GUEST_PENDING_DEBUG);
	report(pending_dbg & DR6_BS,
	       "'pending debug exceptions' field after MTF VM-exit: 0x%lx (expected 0x%lx)",
	       pending_dbg, (unsigned long) DR6_BS);

	disable_mtf();
	disable_tf();
	vmcs_write(GUEST_PENDING_DEBUG, 0);

	/*
	 * #GP exception takes priority over MTF. Expect MTF VM-exit with RIP
	 * advanced to first instruction of #GP handler.
	 */
	enter_guest();
	skip_exit_vmcall();

	old_gp = handle_exception(GP_VECTOR, test_mtf_gp_handler);

	enable_mtf();
	enter_guest();
	report_mtf("MOV CR3", (unsigned long) get_idt_addr(&boot_idt[GP_VECTOR]));
	disable_mtf();

	/*
	 * Concurrent MTF and privileged software exception (i.e. ICEBP/INT1).
	 * MTF should follow the delivery of #DB trap, though the SDM doesn't
	 * provide clear indication of the relative priority.
	 */
	enter_guest();
	skip_exit_vmcall();

	handle_exception(GP_VECTOR, old_gp);
	old_db = handle_exception(DB_VECTOR, test_mtf_db_handler);

	enable_mtf();
	enter_guest();
	report_mtf("INT1", (unsigned long) get_idt_addr(&boot_idt[DB_VECTOR]));
	disable_mtf();

	enter_guest();
	skip_exit_vmcall();
	handle_exception(DB_VECTOR, old_db);
	vmcs_write(ENT_INTR_INFO, INTR_INFO_VALID_MASK | INTR_TYPE_OTHER_EVENT);
	enter_guest();
	report_mtf("injected MTF", (unsigned long) &test_mtf4);
	enter_guest();
}

extern char vmx_mtf_pdpte_guest_begin;
extern char vmx_mtf_pdpte_guest_end;

asm("vmx_mtf_pdpte_guest_begin:\n\t"
    "mov %cr0, %rax\n\t"    /* save CR0 with PG=1                 */
    "vmcall\n\t"            /* on return from this CR0.PG=0       */
    "mov %rax, %cr0\n\t"    /* restore CR0.PG=1 to enter PAE mode */
    "vmcall\n\t"
    "retq\n\t"
    "vmx_mtf_pdpte_guest_end:");

static void vmx_mtf_pdpte_test(void)
{
	void *test_mtf_pdpte_guest;
	pteval_t *pdpt;
	u32 guest_ar_cs;
	u64 guest_efer;
	pteval_t *pte;
	u64 guest_cr0;
	u64 guest_cr3;
	u64 guest_cr4;
	u64 ent_ctls;
	int i;

	if (setup_ept(false))
		return;

	if (!(ctrl_cpu_rev[0].clr & CPU_MTF)) {
		report_skip("%s : \"Monitor trap flag\" exec control not supported", __func__);
		return;
	}

	if (!(ctrl_cpu_rev[1].clr & CPU_URG)) {
		report_skip("%s : \"Unrestricted guest\" exec control not supported", __func__);
		return;
	}

	vmcs_write(EXC_BITMAP, ~0);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | CPU_URG);

	/*
	 * Copy the guest code to an identity-mapped page.
	 */
	test_mtf_pdpte_guest = alloc_page();
	memcpy(test_mtf_pdpte_guest, &vmx_mtf_pdpte_guest_begin,
	       &vmx_mtf_pdpte_guest_end - &vmx_mtf_pdpte_guest_begin);

	test_set_guest(test_mtf_pdpte_guest);

	enter_guest();
	skip_exit_vmcall();

	/*
	 * Put the guest in non-paged 32-bit protected mode, ready to enter
	 * PAE mode when CR0.PG is set. CR4.PAE will already have been set
	 * when the guest started out in long mode.
	 */
	ent_ctls = vmcs_read(ENT_CONTROLS);
	vmcs_write(ENT_CONTROLS, ent_ctls & ~ENT_GUEST_64);

	guest_efer = vmcs_read(GUEST_EFER);
	vmcs_write(GUEST_EFER, guest_efer & ~(EFER_LMA | EFER_LME));

	/*
	 * Set CS access rights bits for 32-bit protected mode:
	 * 3:0    B execute/read/accessed
	 * 4      1 code or data
	 * 6:5    0 descriptor privilege level
	 * 7      1 present
	 * 11:8   0 reserved
	 * 12     0 available for use by system software
	 * 13     0 64 bit mode not active
	 * 14     1 default operation size 32-bit segment
	 * 15     1 page granularity: segment limit in 4K units
	 * 16     0 segment usable
	 * 31:17  0 reserved
	 */
	guest_ar_cs = vmcs_read(GUEST_AR_CS);
	vmcs_write(GUEST_AR_CS, 0xc09b);

	guest_cr0 = vmcs_read(GUEST_CR0);
	vmcs_write(GUEST_CR0, guest_cr0 & ~X86_CR0_PG);

	guest_cr4 = vmcs_read(GUEST_CR4);
	vmcs_write(GUEST_CR4, guest_cr4 & ~X86_CR4_PCIDE);

	guest_cr3 = vmcs_read(GUEST_CR3);

	/*
	 * Turn the 4-level page table into a PAE page table by following the 0th
	 * PML4 entry to a PDPT page, and grab the first four PDPTEs from that
	 * page.
	 *
	 * Why does this work?
	 *
	 * PAE uses 32-bit addressing which implies:
	 * Bits 11:0   page offset
	 * Bits 20:12  entry into 512-entry page table
	 * Bits 29:21  entry into a 512-entry directory table
	 * Bits 31:30  entry into the page directory pointer table.
	 * Bits 63:32  zero
	 *
	 * As only 2 bits are needed to select the PDPTEs for the entire
	 * 32-bit address space, take the first 4 PDPTEs in the level 3 page
	 * directory pointer table. It doesn't matter which of these PDPTEs
	 * are present because they must cover the guest code given that it
	 * has already run successfully.
	 *
	 * Get a pointer to PTE for GVA=0 in the page directory pointer table
	 */
	pte = get_pte_level(
            (pgd_t *)phys_to_virt(guest_cr3 & ~X86_CR3_PCID_MASK), 0,
            PDPT_LEVEL);

	/*
	 * Need some memory for the 4-entry PAE page directory pointer
	 * table. Use the end of the identity-mapped page where the guest code
	 * is stored. There is definitely space as the guest code is only a
	 * few bytes.
	 */
	pdpt = test_mtf_pdpte_guest + PAGE_SIZE - 4 * sizeof(pteval_t);

	/*
	 * Copy the first four PDPTEs into the PAE page table with reserved
	 * bits cleared. Note that permission bits from the PML4E and PDPTE
	 * are not propagated.
	 */
	for (i = 0; i < 4; i++) {
		TEST_ASSERT_EQ_MSG(0, (pte[i] & PDPTE64_RSVD_MASK),
				   "PDPTE has invalid reserved bits");
		TEST_ASSERT_EQ_MSG(0, (pte[i] & PDPTE64_PAGE_SIZE_MASK),
				   "Cannot use 1GB super pages for PAE");
		pdpt[i] = pte[i] & ~(PAE_PDPTE_RSVD_MASK);
	}
	vmcs_write(GUEST_CR3, virt_to_phys(pdpt));

	enable_mtf();
	enter_guest();
	assert_exit_reason(VMX_MTF);
	disable_mtf();

	/*
	 * The four PDPTEs should have been loaded into the VMCS when
	 * the guest set CR0.PG to enter PAE mode.
	 */
	for (i = 0; i < 4; i++) {
		u64 pdpte = vmcs_read(GUEST_PDPTE + 2 * i);

		report(pdpte == pdpt[i], "PDPTE%d is 0x%lx (expected 0x%lx)",
		       i, pdpte, pdpt[i]);
	}

	/*
	 * Now, try to enter the guest in PAE mode. If the PDPTEs in the
	 * vmcs are wrong, this will fail.
	 */
	enter_guest();
	skip_exit_vmcall();

	/*
	 * Return guest to 64-bit mode and wrap up.
	 */
	vmcs_write(ENT_CONTROLS, ent_ctls);
	vmcs_write(GUEST_EFER, guest_efer);
	vmcs_write(GUEST_AR_CS, guest_ar_cs);
	vmcs_write(GUEST_CR0, guest_cr0);
	vmcs_write(GUEST_CR4, guest_cr4);
	vmcs_write(GUEST_CR3, guest_cr3);

	enter_guest();
}

/*
 * Tests for VM-execution control fields
 */
static void test_vm_execution_ctls(void)
{
	test_pin_based_ctls();
	test_primary_processor_based_ctls();
	test_secondary_processor_based_ctls();
	test_cr3_targets();
	test_io_bitmaps();
	test_msr_bitmap();
	test_apic_ctls();
	test_tpr_threshold();
	test_nmi_ctrls();
	test_pml();
	test_vpid();
	test_ept_eptp();
	test_vmx_preemption_timer();
}

 /*
  * The following checks are performed for the VM-entry MSR-load address if
  * the VM-entry MSR-load count field is non-zero:
  *
  *    - The lower 4 bits of the VM-entry MSR-load address must be 0.
  *      The address should not set any bits beyond the processor's
  *      physical-address width.
  *
  *    - The address of the last byte in the VM-entry MSR-load area
  *      should not set any bits beyond the processor's physical-address
  *      width. The address of this last byte is VM-entry MSR-load address
  *      + (MSR count * 16) - 1. (The arithmetic used for the computation
  *      uses more bits than the processor's physical-address width.)
  *
  *
  *  [Intel SDM]
  */
static void test_entry_msr_load(void)
{
	entry_msr_load = alloc_page();
	u64 tmp;
	u32 entry_msr_ld_cnt = 1;
	int i;
	u32 addr_len = 64;

	vmcs_write(ENT_MSR_LD_CNT, entry_msr_ld_cnt);

	/* Check first 4 bits of VM-entry MSR-load address */
	for (i = 0; i < 4; i++) {
		tmp = (u64)entry_msr_load | 1ull << i;
		vmcs_write(ENTER_MSR_LD_ADDR, tmp);
		report_prefix_pushf("VM-entry MSR-load addr [4:0] %lx",
				    tmp & 0xf);
		test_vmx_invalid_controls();
		report_prefix_pop();
	}

	if (basic.val & (1ul << 48))
		addr_len = 32;

	test_vmcs_addr_values("VM-entry-MSR-load address",
				ENTER_MSR_LD_ADDR, 16, false, false,
				4, addr_len - 1);

	/*
	 * Check last byte of VM-entry MSR-load address
	 */
	entry_msr_load = (struct vmx_msr_entry *)((u64)entry_msr_load & ~0xf);

	for (i = (addr_len == 64 ? cpuid_maxphyaddr(): addr_len);
							i < 64; i++) {
		tmp = ((u64)entry_msr_load + entry_msr_ld_cnt * 16 - 1) |
			1ul << i;
		vmcs_write(ENTER_MSR_LD_ADDR,
			   tmp - (entry_msr_ld_cnt * 16 - 1));
		test_vmx_invalid_controls();
	}

	vmcs_write(ENT_MSR_LD_CNT, 2);
	vmcs_write(ENTER_MSR_LD_ADDR, (1ULL << cpuid_maxphyaddr()) - 16);
	test_vmx_invalid_controls();
	vmcs_write(ENTER_MSR_LD_ADDR, (1ULL << cpuid_maxphyaddr()) - 32);
	test_vmx_valid_controls();
	vmcs_write(ENTER_MSR_LD_ADDR, (1ULL << cpuid_maxphyaddr()) - 48);
	test_vmx_valid_controls();
}

static struct vmx_state_area_test_data {
	u32 msr;
	u64 exp;
	bool enabled;
} vmx_state_area_test_data;

static void guest_state_test_main(void)
{
	u64 obs;
	struct vmx_state_area_test_data *data = &vmx_state_area_test_data;

	while (1) {
		if (vmx_get_test_stage() == 2)
			break;

		if (data->enabled) {
			obs = rdmsr(data->msr);
			report(data->exp == obs,
			       "Guest state is 0x%lx (expected 0x%lx)",
			       obs, data->exp);
		}

		vmcall();
	}

	asm volatile("fnop");
}

static void test_guest_state(const char *test, bool xfail, u64 field,
			     const char * field_name)
{
	struct vmentry_result result;
	u8 abort_flags;

	abort_flags = ABORT_ON_EARLY_VMENTRY_FAIL;
	if (!xfail)
		abort_flags = ABORT_ON_INVALID_GUEST_STATE;

	__enter_guest(abort_flags, &result);

	report(result.exit_reason.failed_vmentry == xfail &&
	       ((xfail && result.exit_reason.basic == VMX_FAIL_STATE) ||
	        (!xfail && result.exit_reason.basic == VMX_VMCALL)) &&
		(!xfail || vmcs_read(EXI_QUALIFICATION) == ENTRY_FAIL_DEFAULT),
	        "%s, %s = %lx", test, field_name, field);

	if (!result.exit_reason.failed_vmentry)
		skip_exit_insn();
}

/*
 * Tests for VM-entry control fields
 */
static void test_vm_entry_ctls(void)
{
	test_invalid_event_injection();
	test_entry_msr_load();
}

/*
 * The following checks are performed for the VM-exit MSR-store address if
 * the VM-exit MSR-store count field is non-zero:
 *
 *    - The lower 4 bits of the VM-exit MSR-store address must be 0.
 *      The address should not set any bits beyond the processor's
 *      physical-address width.
 *
 *    - The address of the last byte in the VM-exit MSR-store area
 *      should not set any bits beyond the processor's physical-address
 *      width. The address of this last byte is VM-exit MSR-store address
 *      + (MSR count * 16) - 1. (The arithmetic used for the computation
 *      uses more bits than the processor's physical-address width.)
 *
 * If IA32_VMX_BASIC[48] is read as 1, neither address should set any bits
 * in the range 63:32.
 *
 *  [Intel SDM]
 */
static void test_exit_msr_store(void)
{
	exit_msr_store = alloc_page();
	u64 tmp;
	u32 exit_msr_st_cnt = 1;
	int i;
	u32 addr_len = 64;

	vmcs_write(EXI_MSR_ST_CNT, exit_msr_st_cnt);

	/* Check first 4 bits of VM-exit MSR-store address */
	for (i = 0; i < 4; i++) {
		tmp = (u64)exit_msr_store | 1ull << i;
		vmcs_write(EXIT_MSR_ST_ADDR, tmp);
		report_prefix_pushf("VM-exit MSR-store addr [4:0] %lx",
				    tmp & 0xf);
		test_vmx_invalid_controls();
		report_prefix_pop();
	}

	if (basic.val & (1ul << 48))
		addr_len = 32;

	test_vmcs_addr_values("VM-exit-MSR-store address",
				EXIT_MSR_ST_ADDR, 16, false, false,
				4, addr_len - 1);

	/*
	 * Check last byte of VM-exit MSR-store address
	 */
	exit_msr_store = (struct vmx_msr_entry *)((u64)exit_msr_store & ~0xf);

	for (i = (addr_len == 64 ? cpuid_maxphyaddr(): addr_len);
							i < 64; i++) {
		tmp = ((u64)exit_msr_store + exit_msr_st_cnt * 16 - 1) |
			1ul << i;
		vmcs_write(EXIT_MSR_ST_ADDR,
			   tmp - (exit_msr_st_cnt * 16 - 1));
		test_vmx_invalid_controls();
	}

	vmcs_write(EXI_MSR_ST_CNT, 2);
	vmcs_write(EXIT_MSR_ST_ADDR, (1ULL << cpuid_maxphyaddr()) - 16);
	test_vmx_invalid_controls();
	vmcs_write(EXIT_MSR_ST_ADDR, (1ULL << cpuid_maxphyaddr()) - 32);
	test_vmx_valid_controls();
	vmcs_write(EXIT_MSR_ST_ADDR, (1ULL << cpuid_maxphyaddr()) - 48);
	test_vmx_valid_controls();
}

/*
 * Tests for VM-exit controls
 */
static void test_vm_exit_ctls(void)
{
	test_exit_msr_store();
}

/*
 * Check that the virtual CPU checks all of the VMX controls as
 * documented in the Intel SDM.
 */
static void vmx_controls_test(void)
{
	/*
	 * Bit 1 of the guest's RFLAGS must be 1, or VM-entry will
	 * fail due to invalid guest state, should we make it that
	 * far.
	 */
	vmcs_write(GUEST_RFLAGS, 0);

	test_vm_execution_ctls();
	test_vm_exit_ctls();
	test_vm_entry_ctls();
}

struct apic_reg_virt_config {
	bool apic_register_virtualization;
	bool use_tpr_shadow;
	bool virtualize_apic_accesses;
	bool virtualize_x2apic_mode;
	bool activate_secondary_controls;
};

struct apic_reg_test {
	const char *name;
	struct apic_reg_virt_config apic_reg_virt_config;
};

struct apic_reg_virt_expectation {
	enum Reason rd_exit_reason;
	enum Reason wr_exit_reason;
	u32 val;
	u32 (*virt_fn)(u32);

	/*
	 * If false, accessing the APIC access address from L2 is treated as a
	 * normal memory operation, rather than triggering virtualization.
	 */
	bool virtualize_apic_accesses;
};

static u32 apic_virt_identity(u32 val)
{
	return val;
}

static u32 apic_virt_nibble1(u32 val)
{
	return val & 0xf0;
}

static u32 apic_virt_byte3(u32 val)
{
	return val & (0xff << 24);
}

static bool apic_reg_virt_exit_expectation(
	u32 reg, struct apic_reg_virt_config *config,
	struct apic_reg_virt_expectation *expectation)
{
	/* Good configs, where some L2 APIC accesses are virtualized. */
	bool virtualize_apic_accesses_only =
		config->virtualize_apic_accesses &&
		!config->use_tpr_shadow &&
		!config->apic_register_virtualization &&
		!config->virtualize_x2apic_mode &&
		config->activate_secondary_controls;
	bool virtualize_apic_accesses_and_use_tpr_shadow =
		config->virtualize_apic_accesses &&
		config->use_tpr_shadow &&
		!config->apic_register_virtualization &&
		!config->virtualize_x2apic_mode &&
		config->activate_secondary_controls;
	bool apic_register_virtualization =
		config->virtualize_apic_accesses &&
		config->use_tpr_shadow &&
		config->apic_register_virtualization &&
		!config->virtualize_x2apic_mode &&
		config->activate_secondary_controls;

	expectation->val = MAGIC_VAL_1;
	expectation->virt_fn = apic_virt_identity;
	expectation->virtualize_apic_accesses =
		config->virtualize_apic_accesses &&
		config->activate_secondary_controls;
	if (virtualize_apic_accesses_only) {
		expectation->rd_exit_reason = VMX_APIC_ACCESS;
		expectation->wr_exit_reason = VMX_APIC_ACCESS;
	} else if (virtualize_apic_accesses_and_use_tpr_shadow) {
		switch (reg) {
		case APIC_TASKPRI:
			expectation->rd_exit_reason = VMX_VMCALL;
			expectation->wr_exit_reason = VMX_VMCALL;
			expectation->virt_fn = apic_virt_nibble1;
			break;
		default:
			expectation->rd_exit_reason = VMX_APIC_ACCESS;
			expectation->wr_exit_reason = VMX_APIC_ACCESS;
		}
	} else if (apic_register_virtualization) {
		expectation->rd_exit_reason = VMX_VMCALL;

		switch (reg) {
		case APIC_ID:
		case APIC_EOI:
		case APIC_LDR:
		case APIC_DFR:
		case APIC_SPIV:
		case APIC_ESR:
		case APIC_ICR:
		case APIC_LVTT:
		case APIC_LVTTHMR:
		case APIC_LVTPC:
		case APIC_LVT0:
		case APIC_LVT1:
		case APIC_LVTERR:
		case APIC_TMICT:
		case APIC_TDCR:
			expectation->wr_exit_reason = VMX_APIC_WRITE;
			break;
		case APIC_LVR:
		case APIC_ISR ... APIC_ISR + 0x70:
		case APIC_TMR ... APIC_TMR + 0x70:
		case APIC_IRR ... APIC_IRR + 0x70:
			expectation->wr_exit_reason = VMX_APIC_ACCESS;
			break;
		case APIC_TASKPRI:
			expectation->wr_exit_reason = VMX_VMCALL;
			expectation->virt_fn = apic_virt_nibble1;
			break;
		case APIC_ICR2:
			expectation->wr_exit_reason = VMX_VMCALL;
			expectation->virt_fn = apic_virt_byte3;
			break;
		default:
			expectation->rd_exit_reason = VMX_APIC_ACCESS;
			expectation->wr_exit_reason = VMX_APIC_ACCESS;
		}
	} else if (!expectation->virtualize_apic_accesses) {
		/*
		 * No APIC registers are directly virtualized. This includes
		 * VTPR, which can be virtualized through MOV to/from CR8 via
		 * the use TPR shadow control, but not through directly
		 * accessing VTPR.
		 */
		expectation->rd_exit_reason = VMX_VMCALL;
		expectation->wr_exit_reason = VMX_VMCALL;
	} else {
		printf("Cannot parse APIC register virtualization config:\n"
		       "\tvirtualize_apic_accesses: %d\n"
		       "\tuse_tpr_shadow: %d\n"
		       "\tapic_register_virtualization: %d\n"
		       "\tvirtualize_x2apic_mode: %d\n"
		       "\tactivate_secondary_controls: %d\n",
		       config->virtualize_apic_accesses,
		       config->use_tpr_shadow,
		       config->apic_register_virtualization,
		       config->virtualize_x2apic_mode,
		       config->activate_secondary_controls);

		return false;
	}

	return true;
}

struct apic_reg_test apic_reg_tests[] = {
	/* Good configs, where some L2 APIC accesses are virtualized. */
	{
		.name = "Virtualize APIC accesses",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = false,
			.apic_register_virtualization = false,
			.virtualize_x2apic_mode = false,
			.activate_secondary_controls = true,
		},
	},
	{
		.name = "Virtualize APIC accesses + Use TPR shadow",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = true,
			.apic_register_virtualization = false,
			.virtualize_x2apic_mode = false,
			.activate_secondary_controls = true,
		},
	},
	{
		.name = "APIC-register virtualization",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = true,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = false,
			.activate_secondary_controls = true,
		},
	},

	/*
	 * Test that the secondary processor-based VM-execution controls are
	 * correctly ignored when "activate secondary controls" is disabled.
	 */
	{
		.name = "Activate secondary controls off",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = false,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = false,
		},
	},
	{
		.name = "Activate secondary controls off + Use TPR shadow",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = true,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = false,
		},
	},

	/*
	 * Test that the APIC access address is treated like an arbitrary memory
	 * address when "virtualize APIC accesses" is disabled.
	 */
	{
		.name = "Virtualize APIC accesses off + Use TPR shadow",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = false,
			.use_tpr_shadow = true,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = true,
		},
	},

	/*
	 * Test that VM entry fails due to invalid controls when
	 * "APIC-register virtualization" is enabled while "use TPR shadow" is
	 * disabled.
	 */
	{
		.name = "APIC-register virtualization + Use TPR shadow off",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = false,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = false,
			.activate_secondary_controls = true,
		},
	},

	/*
	 * Test that VM entry fails due to invalid controls when
	 * "Virtualize x2APIC mode" is enabled while "use TPR shadow" is
	 * disabled.
	 */
	{
		.name = "Virtualize x2APIC mode + Use TPR shadow off",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = false,
			.use_tpr_shadow = false,
			.apic_register_virtualization = false,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = true,
		},
	},
	{
		.name = "Virtualize x2APIC mode + Use TPR shadow off v2",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = false,
			.use_tpr_shadow = false,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = true,
		},
	},

	/*
	 * Test that VM entry fails due to invalid controls when
	 * "virtualize x2APIC mode" is enabled while "virtualize APIC accesses"
	 * is enabled.
	 */
	{
		.name = "Virtualize x2APIC mode + Virtualize APIC accesses",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = true,
			.apic_register_virtualization = false,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = true,
		},
	},
	{
		.name = "Virtualize x2APIC mode + Virtualize APIC accesses v2",
		.apic_reg_virt_config = {
			.virtualize_apic_accesses = true,
			.use_tpr_shadow = true,
			.apic_register_virtualization = true,
			.virtualize_x2apic_mode = true,
			.activate_secondary_controls = true,
		},
	},
};

enum Apic_op {
	APIC_OP_XAPIC_RD,
	APIC_OP_XAPIC_WR,
	TERMINATE,
};

static u32 vmx_xapic_read(u32 *apic_access_address, u32 reg)
{
	return *(volatile u32 *)((uintptr_t)apic_access_address + reg);
}

static void vmx_xapic_write(u32 *apic_access_address, u32 reg, u32 val)
{
	*(volatile u32 *)((uintptr_t)apic_access_address + reg) = val;
}

struct apic_reg_virt_guest_args {
	enum Apic_op op;
	u32 *apic_access_address;
	u32 reg;
	u32 val;
	bool check_rd;
	u32 (*virt_fn)(u32);
} apic_reg_virt_guest_args;

static void apic_reg_virt_guest(void)
{
	volatile struct apic_reg_virt_guest_args *args =
		&apic_reg_virt_guest_args;

	for (;;) {
		enum Apic_op op = args->op;
		u32 *apic_access_address = args->apic_access_address;
		u32 reg = args->reg;
		u32 val = args->val;
		bool check_rd = args->check_rd;
		u32 (*virt_fn)(u32) = args->virt_fn;

		if (op == TERMINATE)
			break;

		if (op == APIC_OP_XAPIC_RD) {
			u32 ret = vmx_xapic_read(apic_access_address, reg);

			if (check_rd) {
				u32 want = virt_fn(val);
				u32 got = virt_fn(ret);

				report(got == want,
				       "read 0x%x, expected 0x%x.", got, want);
			}
		} else if (op == APIC_OP_XAPIC_WR) {
			vmx_xapic_write(apic_access_address, reg, val);
		}

		/*
		 * The L1 should always execute a vmcall after it's done testing
		 * an individual APIC operation. This helps to validate that the
		 * L1 and L2 are in sync with each other, as expected.
		 */
		vmcall();
	}
}

static void test_xapic_rd(
	u32 reg, struct apic_reg_virt_expectation *expectation,
	u32 *apic_access_address, u32 *virtual_apic_page)
{
	u32 val = expectation->val;
	u32 exit_reason_want = expectation->rd_exit_reason;
	struct apic_reg_virt_guest_args *args = &apic_reg_virt_guest_args;

	report_prefix_pushf("xapic - reading 0x%03x", reg);

	/* Configure guest to do an xapic read */
	args->op = APIC_OP_XAPIC_RD;
	args->apic_access_address = apic_access_address;
	args->reg = reg;
	args->val = val;
	args->check_rd = exit_reason_want == VMX_VMCALL;
	args->virt_fn = expectation->virt_fn;

	/* Setup virtual APIC page */
	if (!expectation->virtualize_apic_accesses) {
		apic_access_address[apic_reg_index(reg)] = val;
		virtual_apic_page[apic_reg_index(reg)] = 0;
	} else if (exit_reason_want == VMX_VMCALL) {
		apic_access_address[apic_reg_index(reg)] = 0;
		virtual_apic_page[apic_reg_index(reg)] = val;
	}

	/* Enter guest */
	enter_guest();

	/*
	 * Validate the behavior and
	 * pass a magic value back to the guest.
	 */
	if (exit_reason_want == VMX_APIC_ACCESS) {
		u32 apic_page_offset = vmcs_read(EXI_QUALIFICATION) & 0xfff;

		assert_exit_reason(exit_reason_want);
		report(apic_page_offset == reg,
		       "got APIC access exit @ page offset 0x%03x, want 0x%03x",
		       apic_page_offset, reg);
		skip_exit_insn();

		/* Reenter guest so it can consume/check rcx and exit again. */
		enter_guest();
	} else if (exit_reason_want != VMX_VMCALL) {
		report_fail("Oops, bad exit expectation: %u.", exit_reason_want);
	}

	skip_exit_vmcall();
	report_prefix_pop();
}

static void test_xapic_wr(
	u32 reg, struct apic_reg_virt_expectation *expectation,
	u32 *apic_access_address, u32 *virtual_apic_page)
{
	u32 val = expectation->val;
	u32 exit_reason_want = expectation->wr_exit_reason;
	struct apic_reg_virt_guest_args *args = &apic_reg_virt_guest_args;
	bool virtualized =
		expectation->virtualize_apic_accesses &&
		(exit_reason_want == VMX_APIC_WRITE ||
		 exit_reason_want == VMX_VMCALL);
	bool checked = false;

	report_prefix_pushf("xapic - writing 0x%x to 0x%03x", val, reg);

	/* Configure guest to do an xapic read */
	args->op = APIC_OP_XAPIC_WR;
	args->apic_access_address = apic_access_address;
	args->reg = reg;
	args->val = val;

	/* Setup virtual APIC page */
	if (virtualized || !expectation->virtualize_apic_accesses) {
		apic_access_address[apic_reg_index(reg)] = 0;
		virtual_apic_page[apic_reg_index(reg)] = 0;
	}

	/* Enter guest */
	enter_guest();

	/*
	 * Validate the behavior and
	 * pass a magic value back to the guest.
	 */
	if (exit_reason_want == VMX_APIC_ACCESS) {
		u32 apic_page_offset = vmcs_read(EXI_QUALIFICATION) & 0xfff;

		assert_exit_reason(exit_reason_want);
		report(apic_page_offset == reg,
		       "got APIC access exit @ page offset 0x%03x, want 0x%03x",
		       apic_page_offset, reg);
		skip_exit_insn();

		/* Reenter guest so it can consume/check rcx and exit again. */
		enter_guest();
	} else if (exit_reason_want == VMX_APIC_WRITE) {
		assert_exit_reason(exit_reason_want);
		report(virtual_apic_page[apic_reg_index(reg)] == val,
		       "got APIC write exit @ page offset 0x%03x; val is 0x%x, want 0x%x",
		       apic_reg_index(reg),
		       virtual_apic_page[apic_reg_index(reg)], val);
		checked = true;

		/* Reenter guest so it can consume/check rcx and exit again. */
		enter_guest();
	} else if (exit_reason_want != VMX_VMCALL) {
		report_fail("Oops, bad exit expectation: %u.", exit_reason_want);
	}

	assert_exit_reason(VMX_VMCALL);
	if (virtualized && !checked) {
		u32 want = expectation->virt_fn(val);
		u32 got = virtual_apic_page[apic_reg_index(reg)];
		got = expectation->virt_fn(got);

		report(got == want, "exitless write; val is 0x%x, want 0x%x",
		       got, want);
	} else if (!expectation->virtualize_apic_accesses && !checked) {
		u32 got = apic_access_address[apic_reg_index(reg)];

		report(got == val,
		       "non-virtualized write; val is 0x%x, want 0x%x", got,
		       val);
	} else if (!expectation->virtualize_apic_accesses && checked) {
		report_fail("Non-virtualized write was prematurely checked!");
	}

	skip_exit_vmcall();
	report_prefix_pop();
}

enum Config_type {
	CONFIG_TYPE_GOOD,
	CONFIG_TYPE_UNSUPPORTED,
	CONFIG_TYPE_VMENTRY_FAILS_EARLY,
};

static enum Config_type configure_apic_reg_virt_test(
	struct apic_reg_virt_config *apic_reg_virt_config)
{
	u32 cpu_exec_ctrl0 = vmcs_read(CPU_EXEC_CTRL0);
	u32 cpu_exec_ctrl1 = vmcs_read(CPU_EXEC_CTRL1);
	/* Configs where L2 entry fails early, due to invalid controls. */
	bool use_tpr_shadow_incorrectly_off =
		!apic_reg_virt_config->use_tpr_shadow &&
		(apic_reg_virt_config->apic_register_virtualization ||
		 apic_reg_virt_config->virtualize_x2apic_mode) &&
		apic_reg_virt_config->activate_secondary_controls;
	bool virtualize_apic_accesses_incorrectly_on =
		apic_reg_virt_config->virtualize_apic_accesses &&
		apic_reg_virt_config->virtualize_x2apic_mode &&
		apic_reg_virt_config->activate_secondary_controls;
	bool vmentry_fails_early =
		use_tpr_shadow_incorrectly_off ||
		virtualize_apic_accesses_incorrectly_on;

	if (apic_reg_virt_config->activate_secondary_controls) {
		if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY)) {
			printf("VM-execution control \"activate secondary controls\" NOT supported.\n");
			return CONFIG_TYPE_UNSUPPORTED;
		}
		cpu_exec_ctrl0 |= CPU_SECONDARY;
	} else {
		cpu_exec_ctrl0 &= ~CPU_SECONDARY;
	}

	if (apic_reg_virt_config->virtualize_apic_accesses) {
		if (!(ctrl_cpu_rev[1].clr & CPU_VIRT_APIC_ACCESSES)) {
			printf("VM-execution control \"virtualize APIC accesses\" NOT supported.\n");
			return CONFIG_TYPE_UNSUPPORTED;
		}
		cpu_exec_ctrl1 |= CPU_VIRT_APIC_ACCESSES;
	} else {
		cpu_exec_ctrl1 &= ~CPU_VIRT_APIC_ACCESSES;
	}

	if (apic_reg_virt_config->use_tpr_shadow) {
		if (!(ctrl_cpu_rev[0].clr & CPU_TPR_SHADOW)) {
			printf("VM-execution control \"use TPR shadow\" NOT supported.\n");
			return CONFIG_TYPE_UNSUPPORTED;
		}
		cpu_exec_ctrl0 |= CPU_TPR_SHADOW;
	} else {
		cpu_exec_ctrl0 &= ~CPU_TPR_SHADOW;
	}

	if (apic_reg_virt_config->apic_register_virtualization) {
		if (!(ctrl_cpu_rev[1].clr & CPU_APIC_REG_VIRT)) {
			printf("VM-execution control \"APIC-register virtualization\" NOT supported.\n");
			return CONFIG_TYPE_UNSUPPORTED;
		}
		cpu_exec_ctrl1 |= CPU_APIC_REG_VIRT;
	} else {
		cpu_exec_ctrl1 &= ~CPU_APIC_REG_VIRT;
	}

	if (apic_reg_virt_config->virtualize_x2apic_mode) {
		if (!(ctrl_cpu_rev[1].clr & CPU_VIRT_X2APIC)) {
			printf("VM-execution control \"virtualize x2APIC mode\" NOT supported.\n");
			return CONFIG_TYPE_UNSUPPORTED;
		}
		cpu_exec_ctrl1 |= CPU_VIRT_X2APIC;
	} else {
		cpu_exec_ctrl1 &= ~CPU_VIRT_X2APIC;
	}

	vmcs_write(CPU_EXEC_CTRL0, cpu_exec_ctrl0);
	vmcs_write(CPU_EXEC_CTRL1, cpu_exec_ctrl1);

	if (vmentry_fails_early)
		return CONFIG_TYPE_VMENTRY_FAILS_EARLY;

	return CONFIG_TYPE_GOOD;
}

static bool cpu_has_apicv(void)
{
	return ((ctrl_cpu_rev[1].clr & CPU_APIC_REG_VIRT) &&
		(ctrl_cpu_rev[1].clr & CPU_VINTD) &&
		(ctrl_pin_rev.clr & PIN_POST_INTR));
}

/* Validates APIC register access across valid virtualization configurations. */
static void apic_reg_virt_test(void)
{
	u32 *apic_access_address;
	u32 *virtual_apic_page;
	u64 control;
	u64 cpu_exec_ctrl0 = vmcs_read(CPU_EXEC_CTRL0);
	u64 cpu_exec_ctrl1 = vmcs_read(CPU_EXEC_CTRL1);
	int i;
	struct apic_reg_virt_guest_args *args = &apic_reg_virt_guest_args;

	if (!cpu_has_apicv()) {
		report_skip("%s : Not all required APICv bits supported", __func__);
		return;
	}

	control = cpu_exec_ctrl1;
	control &= ~CPU_VINTD;
	vmcs_write(CPU_EXEC_CTRL1, control);

	test_set_guest(apic_reg_virt_guest);

	/*
	 * From the SDM: The 1-setting of the "virtualize APIC accesses"
	 * VM-execution is guaranteed to apply only if translations to the
	 * APIC-access address use a 4-KByte page.
	 */
	apic_access_address = alloc_page();
	force_4k_page(apic_access_address);
	vmcs_write(APIC_ACCS_ADDR, virt_to_phys(apic_access_address));

	virtual_apic_page = alloc_page();
	vmcs_write(APIC_VIRT_ADDR, virt_to_phys(virtual_apic_page));

	for (i = 0; i < ARRAY_SIZE(apic_reg_tests); i++) {
		struct apic_reg_test *apic_reg_test = &apic_reg_tests[i];
		struct apic_reg_virt_config *apic_reg_virt_config =
				&apic_reg_test->apic_reg_virt_config;
		enum Config_type config_type;
		u32 reg;

		printf("--- %s test ---\n", apic_reg_test->name);
		config_type =
			configure_apic_reg_virt_test(apic_reg_virt_config);
		if (config_type == CONFIG_TYPE_UNSUPPORTED) {
			printf("Skip because of missing features.\n");
			continue;
		}

		if (config_type == CONFIG_TYPE_VMENTRY_FAILS_EARLY) {
			enter_guest_with_bad_controls();
			continue;
		}

		for (reg = 0; reg < PAGE_SIZE / sizeof(u32); reg += 0x10) {
			struct apic_reg_virt_expectation expectation = {};
			bool ok;

			ok = apic_reg_virt_exit_expectation(
				reg, apic_reg_virt_config, &expectation);
			if (!ok) {
				report_fail("Malformed test.");
				break;
			}

			test_xapic_rd(reg, &expectation, apic_access_address,
				      virtual_apic_page);
			test_xapic_wr(reg, &expectation, apic_access_address,
				      virtual_apic_page);
		}
	}

	/* Terminate the guest */
	vmcs_write(CPU_EXEC_CTRL0, cpu_exec_ctrl0);
	vmcs_write(CPU_EXEC_CTRL1, cpu_exec_ctrl1);
	args->op = TERMINATE;
	enter_guest();
	assert_exit_reason(VMX_VMCALL);
}

struct virt_x2apic_mode_config {
	struct apic_reg_virt_config apic_reg_virt_config;
	bool virtual_interrupt_delivery;
	bool use_msr_bitmaps;
	bool disable_x2apic_msr_intercepts;
	bool disable_x2apic;
};

struct virt_x2apic_mode_test_case {
	const char *name;
	struct virt_x2apic_mode_config virt_x2apic_mode_config;
};

enum Virt_x2apic_mode_behavior_type {
	X2APIC_ACCESS_VIRTUALIZED,
	X2APIC_ACCESS_PASSED_THROUGH,
	X2APIC_ACCESS_TRIGGERS_GP,
};

struct virt_x2apic_mode_expectation {
	enum Reason rd_exit_reason;
	enum Reason wr_exit_reason;

	/*
	 * RDMSR and WRMSR handle 64-bit values. However, except for ICR, all of
	 * the x2APIC registers are 32 bits. Notice:
	 *   1. vmx_x2apic_read() clears the upper 32 bits for 32-bit registers.
	 *   2. vmx_x2apic_write() expects the val arg to be well-formed.
	 */
	u64 rd_val;
	u64 wr_val;

	/*
	 * Compares input to virtualized output;
	 * 1st arg is pointer to return expected virtualization output.
	 */
	u64 (*virt_fn)(u64);

	enum Virt_x2apic_mode_behavior_type rd_behavior;
	enum Virt_x2apic_mode_behavior_type wr_behavior;
	bool wr_only;
};

static u64 virt_x2apic_mode_identity(u64 val)
{
	return val;
}

static u64 virt_x2apic_mode_nibble1(u64 val)
{
	return val & 0xf0;
}

static void virt_x2apic_mode_rd_expectation(
	u32 reg, bool virt_x2apic_mode_on, bool disable_x2apic,
	bool apic_register_virtualization, bool virtual_interrupt_delivery,
	struct virt_x2apic_mode_expectation *expectation)
{
	bool readable =
		!x2apic_reg_reserved(reg) &&
		reg != APIC_EOI;

	expectation->rd_exit_reason = VMX_VMCALL;
	expectation->virt_fn = virt_x2apic_mode_identity;
	if (virt_x2apic_mode_on && apic_register_virtualization) {
		expectation->rd_val = MAGIC_VAL_1;
		if (reg == APIC_PROCPRI && virtual_interrupt_delivery)
			expectation->virt_fn = virt_x2apic_mode_nibble1;
		else if (reg == APIC_TASKPRI)
			expectation->virt_fn = virt_x2apic_mode_nibble1;
		expectation->rd_behavior = X2APIC_ACCESS_VIRTUALIZED;
	} else if (virt_x2apic_mode_on && !apic_register_virtualization &&
		   reg == APIC_TASKPRI) {
		expectation->rd_val = MAGIC_VAL_1;
		expectation->virt_fn = virt_x2apic_mode_nibble1;
		expectation->rd_behavior = X2APIC_ACCESS_VIRTUALIZED;
	} else if (!disable_x2apic && readable) {
		expectation->rd_val = apic_read(reg);
		expectation->rd_behavior = X2APIC_ACCESS_PASSED_THROUGH;
	} else {
		expectation->rd_behavior = X2APIC_ACCESS_TRIGGERS_GP;
	}
}

/*
 * get_x2apic_wr_val() creates an innocuous write value for an x2APIC register.
 *
 * For writable registers, get_x2apic_wr_val() deposits the write value into the
 * val pointer arg and returns true. For non-writable registers, val is not
 * modified and get_x2apic_wr_val() returns false.
 */
static bool get_x2apic_wr_val(u32 reg, u64 *val)
{
	switch (reg) {
	case APIC_TASKPRI:
		/* Bits 31:8 are reserved. */
		*val &= 0xff;
		break;
	case APIC_EOI:
	case APIC_ESR:
	case APIC_TMICT:
		/*
		 * EOI, ESR: WRMSR of a non-zero value causes #GP(0).
		 * TMICT: A write of 0 to the initial-count register effectively
		 *        stops the local APIC timer, in both one-shot and
		 *        periodic mode.
		 */
		*val = 0;
		break;
	case APIC_SPIV:
	case APIC_LVTT:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
	case APIC_TDCR:
		/*
		 * To avoid writing a 1 to a reserved bit or causing some other
		 * unintended side effect, read the current value and use it as
		 * the write value.
		 */
		*val = apic_read(reg);
		break;
	case APIC_CMCI:
		if (!apic_lvt_entry_supported(6))
			return false;
		*val = apic_read(reg);
		break;
	case APIC_ICR:
		*val = 0x40000 | 0xf1;
		break;
	case APIC_SELF_IPI:
		/*
		 * With special processing (i.e., virtualize x2APIC mode +
		 * virtual interrupt delivery), writing zero causes an
		 * APIC-write VM exit. We plan to add a test for enabling
		 * "virtual-interrupt delivery" in VMCS12, and that's where we
		 * will test a self IPI with special processing.
		 */
		*val = 0x0;
		break;
	default:
		return false;
	}

	return true;
}

static bool special_processing_applies(u32 reg, u64 *val,
				       bool virt_int_delivery)
{
	bool special_processing =
		(reg == APIC_TASKPRI) ||
		(virt_int_delivery &&
		 (reg == APIC_EOI || reg == APIC_SELF_IPI));

	if (special_processing) {
		TEST_ASSERT(get_x2apic_wr_val(reg, val));
		return true;
	}

	return false;
}

static void virt_x2apic_mode_wr_expectation(
	u32 reg, bool virt_x2apic_mode_on, bool disable_x2apic,
	bool virt_int_delivery,
	struct virt_x2apic_mode_expectation *expectation)
{
	expectation->wr_exit_reason = VMX_VMCALL;
	expectation->wr_val = MAGIC_VAL_1;
	expectation->wr_only = false;

	if (virt_x2apic_mode_on &&
	    special_processing_applies(reg, &expectation->wr_val,
				       virt_int_delivery)) {
		expectation->wr_behavior = X2APIC_ACCESS_VIRTUALIZED;
		if (reg == APIC_SELF_IPI)
			expectation->wr_exit_reason = VMX_APIC_WRITE;
	} else if (!disable_x2apic &&
		   get_x2apic_wr_val(reg, &expectation->wr_val)) {
		expectation->wr_behavior = X2APIC_ACCESS_PASSED_THROUGH;
		if (reg == APIC_EOI || reg == APIC_SELF_IPI)
			expectation->wr_only = true;
		if (reg == APIC_ICR)
			expectation->wr_exit_reason = VMX_EXTINT;
	} else {
		expectation->wr_behavior = X2APIC_ACCESS_TRIGGERS_GP;
		/*
		 * Writing 1 to a reserved bit triggers a #GP.
		 * Thus, set the write value to 0, which seems
		 * the most likely to detect a missed #GP.
		 */
		expectation->wr_val = 0;
	}
}

static void virt_x2apic_mode_exit_expectation(
	u32 reg, struct virt_x2apic_mode_config *config,
	struct virt_x2apic_mode_expectation *expectation)
{
	struct apic_reg_virt_config *base_config =
		&config->apic_reg_virt_config;
	bool virt_x2apic_mode_on =
		base_config->virtualize_x2apic_mode &&
		config->use_msr_bitmaps &&
		config->disable_x2apic_msr_intercepts &&
		base_config->activate_secondary_controls;

	virt_x2apic_mode_wr_expectation(
		reg, virt_x2apic_mode_on, config->disable_x2apic,
		config->virtual_interrupt_delivery, expectation);
	virt_x2apic_mode_rd_expectation(
		reg, virt_x2apic_mode_on, config->disable_x2apic,
		base_config->apic_register_virtualization,
		config->virtual_interrupt_delivery, expectation);
}

struct virt_x2apic_mode_test_case virt_x2apic_mode_tests[] = {
	/*
	 * Baseline "virtualize x2APIC mode" configuration:
	 *   - virtualize x2APIC mode
	 *   - virtual-interrupt delivery
	 *   - APIC-register virtualization
	 *   - x2APIC MSR intercepts disabled
	 *
	 * Reads come from virtual APIC page, special processing applies to
	 * VTPR, EOI, and SELF IPI, and all other writes pass through to L1
	 * APIC.
	 */
	{
		.name = "Baseline",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = false,
			.apic_reg_virt_config = {
				.apic_register_virtualization = true,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = true,
				.activate_secondary_controls = true,
			},
		},
	},
	{
		.name = "Baseline w/ x2apic disabled",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = true,
			.apic_reg_virt_config = {
				.apic_register_virtualization = true,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = true,
				.activate_secondary_controls = true,
			},
		},
	},

	/*
	 * Baseline, minus virtual-interrupt delivery. Reads come from virtual
	 * APIC page, special processing applies to VTPR, and all other writes
	 * pass through to L1 APIC.
	 */
	{
		.name = "Baseline - virtual interrupt delivery",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = false,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = false,
			.apic_reg_virt_config = {
				.apic_register_virtualization = true,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = true,
				.activate_secondary_controls = true,
			},
		},
	},

	/*
	 * Baseline, minus APIC-register virtualization. x2APIC reads pass
	 * through to L1's APIC, unless reading VTPR
	 */
	{
		.name = "Virtualize x2APIC mode, no APIC reg virt",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = false,
			.apic_reg_virt_config = {
				.apic_register_virtualization = false,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = true,
				.activate_secondary_controls = true,
			},
		},
	},
	{
		.name = "Virtualize x2APIC mode, no APIC reg virt, x2APIC off",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = true,
			.apic_reg_virt_config = {
				.apic_register_virtualization = false,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = true,
				.activate_secondary_controls = true,
			},
		},
	},

	/*
	 * Enable "virtualize x2APIC mode" and "APIC-register virtualization",
	 * and disable intercepts for the x2APIC MSRs, but fail to enable
	 * "activate secondary controls" (i.e. L2 gets access to L1's x2APIC
	 * MSRs).
	 */
	{
		.name = "Fail to enable activate secondary controls",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = false,
			.apic_reg_virt_config = {
				.apic_register_virtualization = true,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = true,
				.activate_secondary_controls = false,
			},
		},
	},

	/*
	 * Enable "APIC-register virtualization" and enable "activate secondary
	 * controls" and disable intercepts for the x2APIC MSRs, but do not
	 * enable the "virtualize x2APIC mode" VM-execution control (i.e. L2
	 * gets access to L1's x2APIC MSRs).
	 */
	{
		.name = "Fail to enable virtualize x2APIC mode",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = false,
			.apic_reg_virt_config = {
				.apic_register_virtualization = true,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = false,
				.activate_secondary_controls = true,
			},
		},
	},

	/*
	 * Disable "Virtualize x2APIC mode", disable x2APIC MSR intercepts, and
	 * enable "APIC-register virtualization" --> L2 gets L1's x2APIC MSRs.
	 */
	{
		.name = "Baseline",
		.virt_x2apic_mode_config = {
			.virtual_interrupt_delivery = true,
			.use_msr_bitmaps = true,
			.disable_x2apic_msr_intercepts = true,
			.disable_x2apic = false,
			.apic_reg_virt_config = {
				.apic_register_virtualization = true,
				.use_tpr_shadow = true,
				.virtualize_apic_accesses = false,
				.virtualize_x2apic_mode = false,
				.activate_secondary_controls = true,
			},
		},
	},
};

enum X2apic_op {
	X2APIC_OP_RD,
	X2APIC_OP_WR,
	X2APIC_TERMINATE,
};

static u64 vmx_x2apic_read(u32 reg)
{
	u32 msr_addr = x2apic_msr(reg);
	u64 val;

	val = rdmsr(msr_addr);

	return val;
}

static void vmx_x2apic_write(u32 reg, u64 val)
{
	u32 msr_addr = x2apic_msr(reg);

	wrmsr(msr_addr, val);
}

struct virt_x2apic_mode_guest_args {
	enum X2apic_op op;
	u32 reg;
	u64 val;
	bool should_gp;
	u64 (*virt_fn)(u64);
} virt_x2apic_mode_guest_args;

static volatile bool handle_x2apic_gp_ran;
static volatile u32 handle_x2apic_gp_insn_len;
static void handle_x2apic_gp(struct ex_regs *regs)
{
	handle_x2apic_gp_ran = true;
	regs->rip += handle_x2apic_gp_insn_len;
}

static handler setup_x2apic_gp_handler(void)
{
	handler old_handler;

	old_handler = handle_exception(GP_VECTOR, handle_x2apic_gp);
	/* RDMSR and WRMSR are both 2 bytes, assuming no prefixes. */
	handle_x2apic_gp_insn_len = 2;

	return old_handler;
}

static void teardown_x2apic_gp_handler(handler old_handler)
{
	handle_exception(GP_VECTOR, old_handler);

	/*
	 * Defensively reset instruction length, so that if the handler is
	 * incorrectly used, it will loop infinitely, rather than run off into
	 * la la land.
	 */
	handle_x2apic_gp_insn_len = 0;
	handle_x2apic_gp_ran = false;
}

static void virt_x2apic_mode_guest(void)
{
	volatile struct virt_x2apic_mode_guest_args *args =
		&virt_x2apic_mode_guest_args;

	for (;;) {
		enum X2apic_op op = args->op;
		u32 reg = args->reg;
		u64 val = args->val;
		bool should_gp = args->should_gp;
		u64 (*virt_fn)(u64) = args->virt_fn;
		handler old_handler;

		if (op == X2APIC_TERMINATE)
			break;

		if (should_gp) {
			TEST_ASSERT(!handle_x2apic_gp_ran);
			old_handler = setup_x2apic_gp_handler();
		}

		if (op == X2APIC_OP_RD) {
			u64 ret = vmx_x2apic_read(reg);

			if (!should_gp) {
				u64 want = virt_fn(val);
				u64 got = virt_fn(ret);

				report(got == want,
				       "APIC read; got 0x%lx, want 0x%lx.",
				       got, want);
			}
		} else if (op == X2APIC_OP_WR) {
			vmx_x2apic_write(reg, val);
		}

		if (should_gp) {
			report(handle_x2apic_gp_ran,
			       "x2APIC op triggered GP.");
			teardown_x2apic_gp_handler(old_handler);
		}

		/*
		 * The L1 should always execute a vmcall after it's done testing
		 * an individual APIC operation. This helps to validate that the
		 * L1 and L2 are in sync with each other, as expected.
		 */
		vmcall();
	}
}

static void test_x2apic_rd(
	u32 reg, struct virt_x2apic_mode_expectation *expectation,
	u32 *virtual_apic_page)
{
	u64 val = expectation->rd_val;
	u32 exit_reason_want = expectation->rd_exit_reason;
	struct virt_x2apic_mode_guest_args *args = &virt_x2apic_mode_guest_args;

	report_prefix_pushf("x2apic - reading 0x%03x", reg);

	/* Configure guest to do an x2apic read */
	args->op = X2APIC_OP_RD;
	args->reg = reg;
	args->val = val;
	args->should_gp = expectation->rd_behavior == X2APIC_ACCESS_TRIGGERS_GP;
	args->virt_fn = expectation->virt_fn;

	/* Setup virtual APIC page */
	if (expectation->rd_behavior == X2APIC_ACCESS_VIRTUALIZED)
		virtual_apic_page[apic_reg_index(reg)] = (u32)val;

	/* Enter guest */
	enter_guest();

	if (exit_reason_want != VMX_VMCALL) {
		report_fail("Oops, bad exit expectation: %u.", exit_reason_want);
	}

	skip_exit_vmcall();
	report_prefix_pop();
}

static volatile bool handle_x2apic_ipi_ran;
static void handle_x2apic_ipi(isr_regs_t *regs)
{
	handle_x2apic_ipi_ran = true;
	eoi();
}

static void test_x2apic_wr(
	u32 reg, struct virt_x2apic_mode_expectation *expectation,
	u32 *virtual_apic_page)
{
	u64 val = expectation->wr_val;
	u32 exit_reason_want = expectation->wr_exit_reason;
	struct virt_x2apic_mode_guest_args *args = &virt_x2apic_mode_guest_args;
	int ipi_vector = 0xf1;
	u32 restore_val = 0;

	report_prefix_pushf("x2apic - writing 0x%lx to 0x%03x", val, reg);

	/* Configure guest to do an x2apic read */
	args->op = X2APIC_OP_WR;
	args->reg = reg;
	args->val = val;
	args->should_gp = expectation->wr_behavior == X2APIC_ACCESS_TRIGGERS_GP;

	/* Setup virtual APIC page */
	if (expectation->wr_behavior == X2APIC_ACCESS_VIRTUALIZED)
		virtual_apic_page[apic_reg_index(reg)] = 0;
	if (expectation->wr_behavior == X2APIC_ACCESS_PASSED_THROUGH && !expectation->wr_only)
		restore_val = apic_read(reg);

	/* Setup IPI handler */
	handle_x2apic_ipi_ran = false;
	handle_irq(ipi_vector, handle_x2apic_ipi);

	/* Enter guest */
	enter_guest();

	/*
	 * Validate the behavior and
	 * pass a magic value back to the guest.
	 */
	if (exit_reason_want == VMX_EXTINT) {
		assert_exit_reason(exit_reason_want);

		/* Clear the external interrupt. */
		irq_enable();
		asm volatile ("nop");
		irq_disable();
		report(handle_x2apic_ipi_ran,
		       "Got pending interrupt after IRQ enabled.");

		enter_guest();
	} else if (exit_reason_want == VMX_APIC_WRITE) {
		assert_exit_reason(exit_reason_want);
		report(virtual_apic_page[apic_reg_index(reg)] == val,
		       "got APIC write exit @ page offset 0x%03x; val is 0x%x, want 0x%lx",
		       apic_reg_index(reg),
		       virtual_apic_page[apic_reg_index(reg)], val);

		/* Reenter guest so it can consume/check rcx and exit again. */
		enter_guest();
	} else if (exit_reason_want != VMX_VMCALL) {
		report_fail("Oops, bad exit expectation: %u.", exit_reason_want);
	}

	assert_exit_reason(VMX_VMCALL);
	if (expectation->wr_behavior == X2APIC_ACCESS_VIRTUALIZED) {
		u64 want = val;
		u32 got = virtual_apic_page[apic_reg_index(reg)];

		report(got == want, "x2APIC write; got 0x%x, want 0x%lx", got,
		       want);
	} else if (expectation->wr_behavior == X2APIC_ACCESS_PASSED_THROUGH) {
		if (!expectation->wr_only) {
			u32 got = apic_read(reg);
			bool ok;

			/*
			 * When L1's TPR is passed through to L2, the lower
			 * nibble can be lost. For example, if L2 executes
			 * WRMSR(0x808, 0x78), then, L1 might read 0x70.
			 *
			 * Here's how the lower nibble can get lost:
			 *   1. L2 executes WRMSR(0x808, 0x78).
			 *   2. L2 exits to L0 with a WRMSR exit.
			 *   3. L0 emulates WRMSR, by writing L1's TPR.
			 *   4. L0 re-enters L2.
			 *   5. L2 exits to L0 (reason doesn't matter).
			 *   6. L0 reflects L2's exit to L1.
			 *   7. Before entering L1, L0 exits to user-space
			 *      (e.g., to satisfy TPR access reporting).
			 *   8. User-space executes KVM_SET_REGS ioctl, which
			 *      clears the lower nibble of L1's TPR.
			 */
			if (reg == APIC_TASKPRI) {
				got = apic_virt_nibble1(got);
				val = apic_virt_nibble1(val);
			}

			ok = got == val;
			report(ok,
			       "non-virtualized write; val is 0x%x, want 0x%lx",
			       got, val);
			apic_write(reg, restore_val);
		} else {
			report_pass("non-virtualized and write-only OK");
		}
	}
	skip_exit_insn();

	report_prefix_pop();
}

static enum Config_type configure_virt_x2apic_mode_test(
	struct virt_x2apic_mode_config *virt_x2apic_mode_config,
	u8 *msr_bitmap_page)
{
	int msr;
	u32 cpu_exec_ctrl0 = vmcs_read(CPU_EXEC_CTRL0);
	u64 cpu_exec_ctrl1 = vmcs_read(CPU_EXEC_CTRL1);

	/* x2apic-specific VMCS config */
	if (virt_x2apic_mode_config->use_msr_bitmaps) {
		/* virt_x2apic_mode_test() checks for MSR bitmaps support */
		cpu_exec_ctrl0 |= CPU_MSR_BITMAP;
	} else {
		cpu_exec_ctrl0 &= ~CPU_MSR_BITMAP;
	}

	if (virt_x2apic_mode_config->virtual_interrupt_delivery) {
		if (!(ctrl_cpu_rev[1].clr & CPU_VINTD)) {
			report_skip("%s : \"virtual-interrupt delivery\" exec control not supported", __func__);
			return CONFIG_TYPE_UNSUPPORTED;
		}
		cpu_exec_ctrl1 |= CPU_VINTD;
	} else {
		cpu_exec_ctrl1 &= ~CPU_VINTD;
	}

	vmcs_write(CPU_EXEC_CTRL0, cpu_exec_ctrl0);
	vmcs_write(CPU_EXEC_CTRL1, cpu_exec_ctrl1);

	/* x2APIC MSR intercepts are usually off for "Virtualize x2APIC mode" */
	for (msr = 0x800; msr <= 0x8ff; msr++) {
		if (virt_x2apic_mode_config->disable_x2apic_msr_intercepts) {
			clear_bit(msr, msr_bitmap_page + 0x000);
			clear_bit(msr, msr_bitmap_page + 0x800);
		} else {
			set_bit(msr, msr_bitmap_page + 0x000);
			set_bit(msr, msr_bitmap_page + 0x800);
		}
	}

	/* x2APIC mode can impact virtualization */
	reset_apic();
	if (!virt_x2apic_mode_config->disable_x2apic)
		enable_x2apic();

	return configure_apic_reg_virt_test(
		&virt_x2apic_mode_config->apic_reg_virt_config);
}

static void virt_x2apic_mode_test(void)
{
	u32 *virtual_apic_page;
	u8 *msr_bitmap_page;
	u64 cpu_exec_ctrl0 = vmcs_read(CPU_EXEC_CTRL0);
	u64 cpu_exec_ctrl1 = vmcs_read(CPU_EXEC_CTRL1);
	int i;
	struct virt_x2apic_mode_guest_args *args = &virt_x2apic_mode_guest_args;

	if (!cpu_has_apicv()) {
		report_skip("%s : Not all required APICv bits supported", __func__);
		return;
	}

	/*
	 * This is to exercise an issue in KVM's logic to merge L0's and L1's
	 * MSR bitmaps. Previously, an L1 could get at L0's x2APIC MSRs by
	 * writing the IA32_SPEC_CTRL MSR or the IA32_PRED_CMD MSRs. KVM would
	 * then proceed to manipulate the MSR bitmaps, as if VMCS12 had the
	 * "Virtualize x2APIC mod" control set, even when it didn't.
	 */
	if (this_cpu_has(X86_FEATURE_SPEC_CTRL))
		wrmsr(MSR_IA32_SPEC_CTRL, 1);

	/*
	 * Check that VMCS12 supports:
	 *   - "Virtual-APIC address", indicated by "use TPR shadow"
	 *   - "MSR-bitmap address", indicated by "use MSR bitmaps"
	 */
	if (!(ctrl_cpu_rev[0].clr & CPU_TPR_SHADOW)) {
		report_skip("%s : \"Use TPR shadow\" exec control not supported", __func__);
		return;
	} else if (!(ctrl_cpu_rev[0].clr & CPU_MSR_BITMAP)) {
		report_skip("%s : \"Use MSR bitmaps\" exec control not supported", __func__);
		return;
	}

	test_set_guest(virt_x2apic_mode_guest);

	virtual_apic_page = alloc_page();
	vmcs_write(APIC_VIRT_ADDR, virt_to_phys(virtual_apic_page));

	msr_bitmap_page = alloc_page();
	memset(msr_bitmap_page, 0xff, PAGE_SIZE);
	vmcs_write(MSR_BITMAP, virt_to_phys(msr_bitmap_page));

	for (i = 0; i < ARRAY_SIZE(virt_x2apic_mode_tests); i++) {
		struct virt_x2apic_mode_test_case *virt_x2apic_mode_test_case =
			&virt_x2apic_mode_tests[i];
		struct virt_x2apic_mode_config *virt_x2apic_mode_config =
			&virt_x2apic_mode_test_case->virt_x2apic_mode_config;
		enum Config_type config_type;
		u32 reg;

		printf("--- %s test ---\n", virt_x2apic_mode_test_case->name);
		config_type =
			configure_virt_x2apic_mode_test(virt_x2apic_mode_config,
							msr_bitmap_page);
		if (config_type == CONFIG_TYPE_UNSUPPORTED) {
			report_skip("Skip because of missing features.");
			continue;
		} else if (config_type == CONFIG_TYPE_VMENTRY_FAILS_EARLY) {
			enter_guest_with_bad_controls();
			continue;
		}

		for (reg = 0; reg < PAGE_SIZE / sizeof(u32); reg += 0x10) {
			struct virt_x2apic_mode_expectation expectation;

			virt_x2apic_mode_exit_expectation(
				reg, virt_x2apic_mode_config, &expectation);

			test_x2apic_rd(reg, &expectation, virtual_apic_page);
			test_x2apic_wr(reg, &expectation, virtual_apic_page);
		}
	}


	/* Terminate the guest */
	vmcs_write(CPU_EXEC_CTRL0, cpu_exec_ctrl0);
	vmcs_write(CPU_EXEC_CTRL1, cpu_exec_ctrl1);
	args->op = X2APIC_TERMINATE;
	enter_guest();
	assert_exit_reason(VMX_VMCALL);
}

static void test_ctl_reg(const char *cr_name, u64 cr, u64 fixed0, u64 fixed1)
{
	u64 val;
	u64 cr_saved = vmcs_read(cr);
	int i;

	val = fixed0 & fixed1;
	if (cr == HOST_CR4)
		vmcs_write(cr, val | X86_CR4_PAE);
	else
		vmcs_write(cr, val);
	report_prefix_pushf("%s %lx", cr_name, val);
	if (val == fixed0)
		test_vmx_vmlaunch(0);
	else
		test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
	report_prefix_pop();

	for (i = 0; i < 64; i++) {

		/* Set a bit when the corresponding bit in fixed1 is 0 */
		if ((fixed1 & (1ull << i)) == 0) {
			if (cr == HOST_CR4 && ((1ull << i) & X86_CR4_SMEP ||
					       (1ull << i) & X86_CR4_SMAP))
				continue;

			vmcs_write(cr, cr_saved | (1ull << i));
			report_prefix_pushf("%s %llx", cr_name,
						cr_saved | (1ull << i));
			test_vmx_vmlaunch(
				VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
			report_prefix_pop();
		}

		/* Unset a bit when the corresponding bit in fixed0 is 1 */
		if (fixed0 & (1ull << i)) {
			vmcs_write(cr, cr_saved & ~(1ull << i));
			report_prefix_pushf("%s %llx", cr_name,
						cr_saved & ~(1ull << i));
			test_vmx_vmlaunch(
				VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
			report_prefix_pop();
		}
	}

	vmcs_write(cr, cr_saved);
}

/*
 * 1. The CR0 field must not set any bit to a value not supported in VMX
 *    operation.
 * 2. The CR4 field must not set any bit to a value not supported in VMX
 *    operation.
 * 3. On processors that support Intel 64 architecture, the CR3 field must
 *    be such that bits 63:52 and bits in the range 51:32 beyond the
 *    processor's physical-address width must be 0.
 *
 *  [Intel SDM]
 */
static void test_host_ctl_regs(void)
{
	u64 fixed0, fixed1, cr3, cr3_saved;
	int i;

	/* Test CR0 */
	fixed0 = rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	fixed1 = rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	test_ctl_reg("HOST_CR0", HOST_CR0, fixed0, fixed1);

	/* Test CR4 */
	fixed0 = rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	fixed1 = rdmsr(MSR_IA32_VMX_CR4_FIXED1) &
		 ~(X86_CR4_SMEP | X86_CR4_SMAP);
	test_ctl_reg("HOST_CR4", HOST_CR4, fixed0, fixed1);

	/* Test CR3 */
	cr3_saved = vmcs_read(HOST_CR3);
	for (i = cpuid_maxphyaddr(); i < 64; i++) {
		cr3 = cr3_saved | (1ul << i);
		vmcs_write(HOST_CR3, cr3);
		report_prefix_pushf("HOST_CR3 %lx", cr3);
		test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
		report_prefix_pop();
	}

	vmcs_write(HOST_CR3, cr3_saved);
}

static void test_efer_vmlaunch(u32 fld, bool ok)
{
	if (fld == HOST_EFER) {
		if (ok)
			test_vmx_vmlaunch(0);
		else
			test_vmx_vmlaunch2(VMXERR_ENTRY_INVALID_CONTROL_FIELD,
					VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
	} else {
		test_guest_state("EFER test", !ok, GUEST_EFER, "GUEST_EFER");
	}
}

static void test_efer_one(u32 fld, const char * fld_name, u64 efer,
			  u32 ctrl_fld, u64 ctrl,
			  int i, const char *efer_bit_name)
{
	bool ok;

	ok = true;
	if (ctrl_fld == EXI_CONTROLS && (ctrl & EXI_LOAD_EFER)) {
		if (!!(efer & EFER_LMA) != !!(ctrl & EXI_HOST_64))
			ok = false;
		if (!!(efer & EFER_LME) != !!(ctrl & EXI_HOST_64))
			ok = false;
	}
	if (ctrl_fld == ENT_CONTROLS && (ctrl & ENT_LOAD_EFER)) {
		/* Check LMA too since CR0.PG is set.  */
		if (!!(efer & EFER_LMA) != !!(ctrl & ENT_GUEST_64))
			ok = false;
		if (!!(efer & EFER_LME) != !!(ctrl & ENT_GUEST_64))
			ok = false;
	}

	/*
	 * Skip the test if it would enter the guest in 32-bit mode.
	 * Perhaps write the test in assembly and make sure it
	 * can be run in either mode?
	 */
	if (fld == GUEST_EFER && ok && !(ctrl & ENT_GUEST_64))
		return;

	vmcs_write(ctrl_fld, ctrl);
	vmcs_write(fld, efer);
	report_prefix_pushf("%s %s bit turned %s, controls %s",
			    fld_name, efer_bit_name,
			    (i & 1) ? "on" : "off",
			    (i & 2) ? "on" : "off");

	test_efer_vmlaunch(fld, ok);
	report_prefix_pop();
}

static void test_efer_bit(u32 fld, const char * fld_name,
			  u32 ctrl_fld, u64 ctrl_bit, u64 efer_bit,
			  const char *efer_bit_name)
{
	u64 efer_saved = vmcs_read(fld);
	u32 ctrl_saved = vmcs_read(ctrl_fld);
	int i;

	for (i = 0; i < 4; i++) {
		u64 efer = efer_saved & ~efer_bit;
		u64 ctrl = ctrl_saved & ~ctrl_bit;

		if (i & 1)
			efer |= efer_bit;
		if (i & 2)
			ctrl |= ctrl_bit;

		test_efer_one(fld, fld_name, efer, ctrl_fld, ctrl,
			      i, efer_bit_name);
	}

	vmcs_write(ctrl_fld, ctrl_saved);
	vmcs_write(fld, efer_saved);
}

static void test_efer(u32 fld, const char * fld_name, u32 ctrl_fld,
		      u64 ctrl_bit1, u64 ctrl_bit2)
{
	u64 efer_saved = vmcs_read(fld);
	u32 ctrl_saved = vmcs_read(ctrl_fld);
	u64 efer_reserved_bits =  ~((u64)(EFER_SCE | EFER_LME | EFER_LMA));
	u64 i;
	u64 efer;

	if (this_cpu_has(X86_FEATURE_NX))
		efer_reserved_bits &= ~EFER_NX;

	if (!ctrl_bit1) {
		report_skip("%s : \"Load-IA32-EFER\" exit control not supported", __func__);
		goto test_entry_exit_mode;
	}

	report_prefix_pushf("%s %lx", fld_name, efer_saved);
	test_efer_vmlaunch(fld, true);
	report_prefix_pop();

	/*
	 * Check reserved bits
	 */
	vmcs_write(ctrl_fld, ctrl_saved & ~ctrl_bit1);
	for (i = 0; i < 64; i++) {
		if ((1ull << i) & efer_reserved_bits) {
			efer = efer_saved | (1ull << i);
			vmcs_write(fld, efer);
			report_prefix_pushf("%s %lx", fld_name, efer);
			test_efer_vmlaunch(fld, true);
			report_prefix_pop();
		}
	}

	vmcs_write(ctrl_fld, ctrl_saved | ctrl_bit1);
	for (i = 0; i < 64; i++) {
		if ((1ull << i) & efer_reserved_bits) {
			efer = efer_saved | (1ull << i);
			vmcs_write(fld, efer);
			report_prefix_pushf("%s %lx", fld_name, efer);
			test_efer_vmlaunch(fld, false);
			report_prefix_pop();
		}
	}

	vmcs_write(ctrl_fld, ctrl_saved);
	vmcs_write(fld, efer_saved);

	/*
	 * Check LMA and LME bits
	 */
	test_efer_bit(fld, fld_name,
		      ctrl_fld, ctrl_bit1,
		      EFER_LMA,
		      "EFER_LMA");
	test_efer_bit(fld, fld_name,
		      ctrl_fld, ctrl_bit1,
		      EFER_LME,
		      "EFER_LME");

test_entry_exit_mode:
	test_efer_bit(fld, fld_name,
		      ctrl_fld, ctrl_bit2,
		      EFER_LMA,
		      "EFER_LMA");
	test_efer_bit(fld, fld_name,
		      ctrl_fld, ctrl_bit2,
		      EFER_LME,
		      "EFER_LME");
}

/*
 * If the 'load IA32_EFER' VM-exit control is 1, bits reserved in the
 * IA32_EFER MSR must be 0 in the field for that register. In addition,
 * the values of the LMA and LME bits in the field must each be that of
 * the 'host address-space size' VM-exit control.
 *
 *  [Intel SDM]
 */
static void test_host_efer(void)
{
	test_efer(HOST_EFER, "HOST_EFER", EXI_CONTROLS, 
		  ctrl_exit_rev.clr & EXI_LOAD_EFER,
		  EXI_HOST_64);
}

/*
 * If the 'load IA32_EFER' VM-enter control is 1, bits reserved in the
 * IA32_EFER MSR must be 0 in the field for that register. In addition,
 * the values of the LMA and LME bits in the field must each be that of
 * the 'IA32e-mode guest' VM-exit control.
 */
static void test_guest_efer(void)
{
	if (!(ctrl_enter_rev.clr & ENT_LOAD_EFER)) {
		report_skip("%s : \"Load-IA32-EFER\" entry control not supported", __func__);
		return;
	}

	vmcs_write(GUEST_EFER, rdmsr(MSR_EFER));
	test_efer(GUEST_EFER, "GUEST_EFER", ENT_CONTROLS,
		  ctrl_enter_rev.clr & ENT_LOAD_EFER,
		  ENT_GUEST_64);
}

/*
 * PAT values higher than 8 are uninteresting since they're likely lumped
 * in with "8". We only test values above 8 one bit at a time,
 * in order to reduce the number of VM-Entries and keep the runtime reasonable.
 */
#define	PAT_VAL_LIMIT	8

static void test_pat(u32 field, const char * field_name, u32 ctrl_field,
		     u64 ctrl_bit)
{
	u32 ctrl_saved = vmcs_read(ctrl_field);
	u64 pat_saved = vmcs_read(field);
	u64 i, val;
	u32 j;
	int error;

	vmcs_clear_bits(ctrl_field, ctrl_bit);

	for (i = 0; i < 256; i = (i < PAT_VAL_LIMIT) ? i + 1 : i * 2) {
		/* Test PAT0..PAT7 fields */
		for (j = 0; j < (i ? 8 : 1); j++) {
			val = i << j * 8;
			vmcs_write(field, val);
			if (field == HOST_PAT) {
				report_prefix_pushf("%s %lx", field_name, val);
				test_vmx_vmlaunch(0);
				report_prefix_pop();

			} else {	// GUEST_PAT
				test_guest_state("ENT_LOAD_PAT enabled", false,
						 val, "GUEST_PAT");
			}
		}
	}

	vmcs_set_bits(ctrl_field, ctrl_bit);
	for (i = 0; i < 256; i = (i < PAT_VAL_LIMIT) ? i + 1 : i * 2) {
		/* Test PAT0..PAT7 fields */
		for (j = 0; j < (i ? 8 : 1); j++) {
			val = i << j * 8;
			vmcs_write(field, val);

			if (field == HOST_PAT) {
				report_prefix_pushf("%s %lx", field_name, val);
				if (i == 0x2 || i == 0x3 || i >= 0x8)
					error =
					VMXERR_ENTRY_INVALID_HOST_STATE_FIELD;
				else
					error = 0;

				test_vmx_vmlaunch(error);
				report_prefix_pop();

			} else {	// GUEST_PAT
				error = (i == 0x2 || i == 0x3 || i >= 0x8);
				test_guest_state("ENT_LOAD_PAT enabled", !!error,
						 val, "GUEST_PAT");
			}

		}
	}

	vmcs_write(ctrl_field, ctrl_saved);
	vmcs_write(field, pat_saved);
}

/*
 *  If the "load IA32_PAT" VM-exit control is 1, the value of the field
 *  for the IA32_PAT MSR must be one that could be written by WRMSR
 *  without fault at CPL 0. Specifically, each of the 8 bytes in the
 *  field must have one of the values 0 (UC), 1 (WC), 4 (WT), 5 (WP),
 *  6 (WB), or 7 (UC-).
 *
 *  [Intel SDM]
 */
static void test_load_host_pat(void)
{
	/*
	 * "load IA32_PAT" VM-exit control
	 */
	if (!(ctrl_exit_rev.clr & EXI_LOAD_PAT)) {
		report_skip("%s : \"Load-IA32-PAT\" exit control not supported", __func__);
		return;
	}

	test_pat(HOST_PAT, "HOST_PAT", EXI_CONTROLS, EXI_LOAD_PAT);
}

union cpuidA_eax {
	struct {
		unsigned int version_id:8;
		unsigned int num_counters_gp:8;
		unsigned int bit_width:8;
		unsigned int mask_length:8;
	} split;
	unsigned int full;
};

union cpuidA_edx {
	struct {
		unsigned int num_counters_fixed:5;
		unsigned int bit_width_fixed:8;
		unsigned int reserved:9;
	} split;
	unsigned int full;
};

static bool valid_pgc(u64 val)
{
	struct cpuid id;
	union cpuidA_eax eax;
	union cpuidA_edx edx;
	u64 mask;

	id = cpuid(0xA);
	eax.full = id.a;
	edx.full = id.d;
	mask = ~(((1ull << eax.split.num_counters_gp) - 1) |
		 (((1ull << edx.split.num_counters_fixed) - 1) << 32));

	return !(val & mask);
}

static void test_pgc_vmlaunch(u32 xerror, u32 xreason, bool xfail, bool host)
{
	u32 inst_err;
	u64 obs;
	bool success;
	struct vmx_state_area_test_data *data = &vmx_state_area_test_data;

	if (host) {
		success = vmlaunch_succeeds();
		obs = rdmsr(data->msr);
		if (!success) {
			inst_err = vmcs_read(VMX_INST_ERROR);
			report(xerror == inst_err, "vmlaunch failed, "
			       "VMX Inst Error is %d (expected %d)",
			       inst_err, xerror);
		} else {
			report(!data->enabled || data->exp == obs,
			       "Host state is 0x%lx (expected 0x%lx)",
			       obs, data->exp);
			report(success != xfail, "vmlaunch succeeded");
		}
	} else {
		test_guest_state("load GUEST_PERF_GLOBAL_CTRL", xfail,
				 GUEST_PERF_GLOBAL_CTRL,
				 "GUEST_PERF_GLOBAL_CTRL");
	}
}

/*
 * test_load_perf_global_ctrl is a generic function for testing the
 * "load IA32_PERF_GLOBAL_CTRL" VM-{Entry,Exit} controls. This test function
 * tests the provided ctrl_val when disabled and enabled.
 *
 * @nr: VMCS field number corresponding to the host/guest state field
 * @name: Name of the above VMCS field for printing in test report
 * @ctrl_nr: VMCS field number corresponding to the VM-{Entry,Exit} control
 * @ctrl_val: Bit to set on the ctrl_field
 */
static void test_perf_global_ctrl(u32 nr, const char *name, u32 ctrl_nr,
				  const char *ctrl_name, u64 ctrl_val)
{
	u64 ctrl_saved = vmcs_read(ctrl_nr);
	u64 pgc_saved = vmcs_read(nr);
	u64 i, val;
	bool host = nr == HOST_PERF_GLOBAL_CTRL;
	struct vmx_state_area_test_data *data = &vmx_state_area_test_data;

	data->msr = MSR_CORE_PERF_GLOBAL_CTRL;
	msr_bmp_init();
	vmcs_write(ctrl_nr, ctrl_saved & ~ctrl_val);
	data->enabled = false;
	report_prefix_pushf("\"load IA32_PERF_GLOBAL_CTRL\"=0 on %s",
			    ctrl_name);

	for (i = 0; i < 64; i++) {
		val = 1ull << i;
		vmcs_write(nr, val);
		report_prefix_pushf("%s = 0x%lx", name, val);
		test_pgc_vmlaunch(0, VMX_VMCALL, false, host);
		report_prefix_pop();
	}
	report_prefix_pop();

	vmcs_write(ctrl_nr, ctrl_saved | ctrl_val);
	data->enabled = true;
	report_prefix_pushf("\"load IA32_PERF_GLOBAL_CTRL\"=1 on %s",
			    ctrl_name);
	for (i = 0; i < 64; i++) {
		val = 1ull << i;
		data->exp = val;
		vmcs_write(nr, val);
		report_prefix_pushf("%s = 0x%lx", name, val);
		if (valid_pgc(val)) {
			test_pgc_vmlaunch(0, VMX_VMCALL, false, host);
		} else {
			if (host)
				test_pgc_vmlaunch(
					VMXERR_ENTRY_INVALID_HOST_STATE_FIELD,
					0,
					true,
					host);
			else
				test_pgc_vmlaunch(
					0,
					VMX_ENTRY_FAILURE | VMX_FAIL_STATE,
					true,
					host);
		}
		report_prefix_pop();
	}

	data->enabled = false;
	report_prefix_pop();
	vmcs_write(ctrl_nr, ctrl_saved);
	vmcs_write(nr, pgc_saved);
}

static void test_load_host_perf_global_ctrl(void)
{
	if (!this_cpu_has_perf_global_ctrl()) {
		report_skip("%s : \"IA32_PERF_GLOBAL_CTRL\" MSR not supported", __func__);
		return;
	}

	if (!(ctrl_exit_rev.clr & EXI_LOAD_PERF)) {
		report_skip("%s : \"Load IA32_PERF_GLOBAL_CTRL\" exit control not supported", __func__);
		return;
	}

	test_perf_global_ctrl(HOST_PERF_GLOBAL_CTRL, "HOST_PERF_GLOBAL_CTRL",
				   EXI_CONTROLS, "EXI_CONTROLS", EXI_LOAD_PERF);
}


static void test_load_guest_perf_global_ctrl(void)
{
	if (!this_cpu_has_perf_global_ctrl()) {
		report_skip("%s : \"IA32_PERF_GLOBAL_CTRL\" MSR not supported", __func__);
		return;
	}

	if (!(ctrl_enter_rev.clr & ENT_LOAD_PERF)) {
		report_skip("%s : \"Load IA32_PERF_GLOBAL_CTRL\" entry control not supported", __func__);
		return;
	}

	test_perf_global_ctrl(GUEST_PERF_GLOBAL_CTRL, "GUEST_PERF_GLOBAL_CTRL",
				   ENT_CONTROLS, "ENT_CONTROLS", ENT_LOAD_PERF);
}


/*
 * test_vmcs_field - test a value for the given VMCS field
 * @field: VMCS field
 * @field_name: string name of VMCS field
 * @bit_start: starting bit
 * @bit_end: ending bit
 * @val: value that the bit range must or must not contain
 * @valid_val: whether value given in 'val' must be valid or not
 * @error: expected VMCS error when vmentry fails for an invalid value
 */
static void test_vmcs_field(u64 field, const char *field_name, u32 bit_start,
			    u32 bit_end, u64 val, bool valid_val, u32 error)
{
	u64 field_saved = vmcs_read(field);
	u32 i;
	u64 tmp;
	u32 bit_on;
	u64 mask = ~0ull;

	mask = (mask >> bit_end) << bit_end;
	mask = mask | ((1 << bit_start) - 1);
	tmp = (field_saved & mask) | (val << bit_start);

	vmcs_write(field, tmp);
	report_prefix_pushf("%s %lx", field_name, tmp);
	if (valid_val)
		test_vmx_vmlaunch(0);
	else
		test_vmx_vmlaunch(error);
	report_prefix_pop();

	for (i = bit_start; i <= bit_end; i = i + 2) {
		bit_on = ((1ull < i) & (val << bit_start)) ? 0 : 1;
		if (bit_on)
			tmp = field_saved | (1ull << i);
		else
			tmp = field_saved & ~(1ull << i);
		vmcs_write(field, tmp);
		report_prefix_pushf("%s %lx", field_name, tmp);
		if (valid_val)
			test_vmx_vmlaunch(error);
		else
			test_vmx_vmlaunch(0);
		report_prefix_pop();
	}

	vmcs_write(field, field_saved);
}

static void test_canonical(u64 field, const char * field_name, bool host)
{
	u64 addr_saved = vmcs_read(field);

	/*
	 * Use the existing value if possible.  Writing a random canonical
	 * value is not an option as doing so would corrupt the field being
	 * tested and likely hose the test.
	 */
	if (is_canonical(addr_saved)) {
		if (host) {
			report_prefix_pushf("%s %lx", field_name, addr_saved);
			test_vmx_vmlaunch(0);
			report_prefix_pop();
		} else {
			test_guest_state("Test canonical address", false,
					 addr_saved, field_name);
		}
	}

	vmcs_write(field, NONCANONICAL);

	if (host) {
		report_prefix_pushf("%s %llx", field_name, NONCANONICAL);
		test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
		report_prefix_pop();
	} else {
		test_guest_state("Test non-canonical address", true,
				 NONCANONICAL, field_name);
	}

	vmcs_write(field, addr_saved);
}

#define TEST_RPL_TI_FLAGS(reg, name)				\
	test_vmcs_field(reg, name, 0, 2, 0x0, true,		\
			VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);

#define TEST_CS_TR_FLAGS(reg, name)				\
	test_vmcs_field(reg, name, 3, 15, 0x0000, false,	\
			VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);

/*
 * 1. In the selector field for each of CS, SS, DS, ES, FS, GS and TR, the
 *    RPL (bits 1:0) and the TI flag (bit 2) must be 0.
 * 2. The selector fields for CS and TR cannot be 0000H.
 * 3. The selector field for SS cannot be 0000H if the "host address-space
 *    size" VM-exit control is 0.
 * 4. On processors that support Intel 64 architecture, the base-address
 *    fields for FS, GS and TR must contain canonical addresses.
 */
static void test_host_segment_regs(void)
{
	u16 selector_saved;

	/*
	 * Test RPL and TI flags
	 */
	TEST_RPL_TI_FLAGS(HOST_SEL_CS, "HOST_SEL_CS");
	TEST_RPL_TI_FLAGS(HOST_SEL_SS, "HOST_SEL_SS");
	TEST_RPL_TI_FLAGS(HOST_SEL_DS, "HOST_SEL_DS");
	TEST_RPL_TI_FLAGS(HOST_SEL_ES, "HOST_SEL_ES");
	TEST_RPL_TI_FLAGS(HOST_SEL_FS, "HOST_SEL_FS");
	TEST_RPL_TI_FLAGS(HOST_SEL_GS, "HOST_SEL_GS");
	TEST_RPL_TI_FLAGS(HOST_SEL_TR, "HOST_SEL_TR");

	/*
	 * Test that CS and TR fields can not be 0x0000
	 */
	TEST_CS_TR_FLAGS(HOST_SEL_CS, "HOST_SEL_CS");
	TEST_CS_TR_FLAGS(HOST_SEL_TR, "HOST_SEL_TR");

	/*
	 * SS field can not be 0x0000 if "host address-space size" VM-exit
	 * control is 0
	 */
	selector_saved = vmcs_read(HOST_SEL_SS);
	vmcs_write(HOST_SEL_SS, 0);
	report_prefix_pushf("HOST_SEL_SS 0");
	if (vmcs_read(EXI_CONTROLS) & EXI_HOST_64) {
		test_vmx_vmlaunch(0);
	} else {
		test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
	}
	report_prefix_pop();

	vmcs_write(HOST_SEL_SS, selector_saved);

	/*
	 * Base address for FS, GS and TR must be canonical
	 */
	test_canonical(HOST_BASE_FS, "HOST_BASE_FS", true);
	test_canonical(HOST_BASE_GS, "HOST_BASE_GS", true);
	test_canonical(HOST_BASE_TR, "HOST_BASE_TR", true);
}

/*
 *  On processors that support Intel 64 architecture, the base-address
 *  fields for GDTR and IDTR must contain canonical addresses.
 */
static void test_host_desc_tables(void)
{
	test_canonical(HOST_BASE_GDTR, "HOST_BASE_GDTR", true);
	test_canonical(HOST_BASE_IDTR, "HOST_BASE_IDTR", true);
}

/*
 * If the "host address-space size" VM-exit control is 0, the following must
 * hold:
 *    - The "IA-32e mode guest" VM-entry control is 0.
 *    - Bit 17 of the CR4 field (corresponding to CR4.PCIDE) is 0.
 *    - Bits 63:32 in the RIP field are 0.
 *
 * If the "host address-space size" VM-exit control is 1, the following must
 * hold:
 *    - Bit 5 of the CR4 field (corresponding to CR4.PAE) is 1.
 *    - The RIP field contains a canonical address.
 *
 */
static void test_host_addr_size(void)
{
	u64 cr4_saved = vmcs_read(HOST_CR4);
	u64 rip_saved = vmcs_read(HOST_RIP);
	u64 entry_ctrl_saved = vmcs_read(ENT_CONTROLS);
	int i;
	u64 tmp;

	if (vmcs_read(EXI_CONTROLS) & EXI_HOST_64) {
		vmcs_write(ENT_CONTROLS, entry_ctrl_saved | ENT_GUEST_64);
		report_prefix_pushf("\"IA-32e mode guest\" enabled");
		test_vmx_vmlaunch(0);
		report_prefix_pop();

		vmcs_write(HOST_CR4, cr4_saved | X86_CR4_PCIDE);
		report_prefix_pushf("\"CR4.PCIDE\" set");
		test_vmx_vmlaunch(0);
		report_prefix_pop();

		for (i = 32; i <= 63; i = i + 4) {
			tmp = rip_saved | 1ull << i;
			vmcs_write(HOST_RIP, tmp);
			report_prefix_pushf("HOST_RIP %lx", tmp);
			test_vmx_vmlaunch(0);
			report_prefix_pop();
		}

		if (cr4_saved & X86_CR4_PAE) {
			vmcs_write(HOST_CR4, cr4_saved  & ~X86_CR4_PAE);
			report_prefix_pushf("\"CR4.PAE\" unset");
			test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
		} else {
			report_prefix_pushf("\"CR4.PAE\" set");
			test_vmx_vmlaunch(0);
		}
		report_prefix_pop();

		vmcs_write(HOST_RIP, NONCANONICAL);
		report_prefix_pushf("HOST_RIP %llx", NONCANONICAL);
		test_vmx_vmlaunch(VMXERR_ENTRY_INVALID_HOST_STATE_FIELD);
		report_prefix_pop();

		vmcs_write(ENT_CONTROLS, entry_ctrl_saved | ENT_GUEST_64);
		vmcs_write(HOST_RIP, rip_saved);
		vmcs_write(HOST_CR4, cr4_saved);

		/* Restore host's active RIP and CR4 values. */
		report_prefix_pushf("restore host state");
		test_vmx_vmlaunch(0);
		report_prefix_pop();
	}
}

/*
 * Check that the virtual CPU checks the VMX Host State Area as
 * documented in the Intel SDM.
 */
static void vmx_host_state_area_test(void)
{
	/*
	 * Bit 1 of the guest's RFLAGS must be 1, or VM-entry will
	 * fail due to invalid guest state, should we make it that
	 * far.
	 */
	vmcs_write(GUEST_RFLAGS, 0);

	test_host_ctl_regs();

	test_canonical(HOST_SYSENTER_ESP, "HOST_SYSENTER_ESP", true);
	test_canonical(HOST_SYSENTER_EIP, "HOST_SYSENTER_EIP", true);

	test_host_efer();
	test_load_host_pat();
	test_host_segment_regs();
	test_host_desc_tables();
	test_host_addr_size();
	test_load_host_perf_global_ctrl();
}

/*
 * If the "load debug controls" VM-entry control is 1, bits 63:32 in
 * the DR7 field must be 0.
 *
 * [Intel SDM]
 */
static void test_guest_dr7(void)
{
	u32 ent_saved = vmcs_read(ENT_CONTROLS);
	u64 dr7_saved = vmcs_read(GUEST_DR7);
	u64 val;
	int i;

	if (ctrl_enter_rev.set & ENT_LOAD_DBGCTLS) {
		vmcs_clear_bits(ENT_CONTROLS, ENT_LOAD_DBGCTLS);
		for (i = 0; i < 64; i++) {
			val = 1ull << i;
			vmcs_write(GUEST_DR7, val);
			test_guest_state("ENT_LOAD_DBGCTLS disabled", false,
					 val, "GUEST_DR7");
		}
	}
	if (ctrl_enter_rev.clr & ENT_LOAD_DBGCTLS) {
		vmcs_set_bits(ENT_CONTROLS, ENT_LOAD_DBGCTLS);
		for (i = 0; i < 64; i++) {
			val = 1ull << i;
			vmcs_write(GUEST_DR7, val);
			test_guest_state("ENT_LOAD_DBGCTLS enabled", i >= 32,
					 val, "GUEST_DR7");
		}
	}
	vmcs_write(GUEST_DR7, dr7_saved);
	vmcs_write(ENT_CONTROLS, ent_saved);
}

/*
 *  If the "load IA32_PAT" VM-entry control is 1, the value of the field
 *  for the IA32_PAT MSR must be one that could be written by WRMSR
 *  without fault at CPL 0. Specifically, each of the 8 bytes in the
 *  field must have one of the values 0 (UC), 1 (WC), 4 (WT), 5 (WP),
 *  6 (WB), or 7 (UC-).
 *
 *  [Intel SDM]
 */
static void test_load_guest_pat(void)
{
	/*
	 * "load IA32_PAT" VM-entry control
	 */
	if (!(ctrl_enter_rev.clr & ENT_LOAD_PAT)) {
		report_skip("%s : \"Load-IA32-PAT\" entry control not supported", __func__);
		return;
	}

	test_pat(GUEST_PAT, "GUEST_PAT", ENT_CONTROLS, ENT_LOAD_PAT);
}

#define MSR_IA32_BNDCFGS_RSVD_MASK	0x00000ffc

/*
 * If the "load IA32_BNDCFGS" VM-entry control is 1, the following
 * checks are performed on the field for the IA32_BNDCFGS MSR:
 *
 *   - Bits reserved in the IA32_BNDCFGS MSR must be 0.
 *   - The linear address in bits 63:12 must be canonical.
 *
 *  [Intel SDM]
 */
static void test_load_guest_bndcfgs(void)
{
	u64 bndcfgs_saved = vmcs_read(GUEST_BNDCFGS);
	u64 bndcfgs;

	if (!(ctrl_enter_rev.clr & ENT_LOAD_BNDCFGS)) {
		report_skip("%s : \"Load-IA32-BNDCFGS\" entry control not supported", __func__);
		return;
	}

	vmcs_clear_bits(ENT_CONTROLS, ENT_LOAD_BNDCFGS);

	vmcs_write(GUEST_BNDCFGS, NONCANONICAL);
	test_guest_state("ENT_LOAD_BNDCFGS disabled", false,
			 GUEST_BNDCFGS, "GUEST_BNDCFGS");
	bndcfgs = bndcfgs_saved | MSR_IA32_BNDCFGS_RSVD_MASK;
	vmcs_write(GUEST_BNDCFGS, bndcfgs);
	test_guest_state("ENT_LOAD_BNDCFGS disabled", false,
			 GUEST_BNDCFGS, "GUEST_BNDCFGS");

	vmcs_set_bits(ENT_CONTROLS, ENT_LOAD_BNDCFGS);

	vmcs_write(GUEST_BNDCFGS, NONCANONICAL);
	test_guest_state("ENT_LOAD_BNDCFGS enabled", true,
			 GUEST_BNDCFGS, "GUEST_BNDCFGS");
	bndcfgs = bndcfgs_saved | MSR_IA32_BNDCFGS_RSVD_MASK;
	vmcs_write(GUEST_BNDCFGS, bndcfgs);
	test_guest_state("ENT_LOAD_BNDCFGS enabled", true,
			 GUEST_BNDCFGS, "GUEST_BNDCFGS");

	vmcs_write(GUEST_BNDCFGS, bndcfgs_saved);
}

#define	GUEST_SEG_UNUSABLE_MASK	(1u << 16)
#define	GUEST_SEG_SEL_TI_MASK	(1u << 2)


#define	TEST_SEGMENT_SEL(test, xfail, sel, val)				\
do {									\
	vmcs_write(sel, val);						\
	test_guest_state(test " segment", xfail, val, xstr(sel));	\
} while (0)

#define	TEST_INVALID_SEG_SEL(sel, val) \
	TEST_SEGMENT_SEL("Invalid: " xstr(val), true, sel, val);

#define	TEST_VALID_SEG_SEL(sel, val) \
	TEST_SEGMENT_SEL("Valid: " xstr(val), false, sel, val);

/*
 * The following checks are done on the Selector field of the Guest Segment
 * Registers:
 *    - TR. The TI flag (bit 2) must be 0.
 *    - LDTR. If LDTR is usable, the TI flag (bit 2) must be 0.
 *    - SS. If the guest will not be virtual-8086 and the "unrestricted
 *	guest" VM-execution control is 0, the RPL (bits 1:0) must equal
 *	the RPL of the selector field for CS.
 *
 *  [Intel SDM]
 */
static void test_guest_segment_sel_fields(void)
{
	u16 sel_saved;
	u32 ar_saved;
	u32 cpu_ctrl0_saved;
	u32 cpu_ctrl1_saved;
	u16 cs_rpl_bits;

	/*
	 * Test for GUEST_SEL_TR
	 */
	sel_saved = vmcs_read(GUEST_SEL_TR);
	TEST_INVALID_SEG_SEL(GUEST_SEL_TR, sel_saved | GUEST_SEG_SEL_TI_MASK);
	vmcs_write(GUEST_SEL_TR, sel_saved);

	/*
	 * Test for GUEST_SEL_LDTR
	 */
	sel_saved = vmcs_read(GUEST_SEL_LDTR);
	ar_saved = vmcs_read(GUEST_AR_LDTR);
	/* LDTR is set unusable */
	vmcs_write(GUEST_AR_LDTR, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_VALID_SEG_SEL(GUEST_SEL_LDTR, sel_saved | GUEST_SEG_SEL_TI_MASK);
	TEST_VALID_SEG_SEL(GUEST_SEL_LDTR, sel_saved & ~GUEST_SEG_SEL_TI_MASK);
	/* LDTR is set usable */
	vmcs_write(GUEST_AR_LDTR, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	TEST_INVALID_SEG_SEL(GUEST_SEL_LDTR, sel_saved | GUEST_SEG_SEL_TI_MASK);

	TEST_VALID_SEG_SEL(GUEST_SEL_LDTR, sel_saved & ~GUEST_SEG_SEL_TI_MASK);

	vmcs_write(GUEST_AR_LDTR, ar_saved);
	vmcs_write(GUEST_SEL_LDTR, sel_saved);

	/*
	 * Test for GUEST_SEL_SS
	 */
	cpu_ctrl0_saved = vmcs_read(CPU_EXEC_CTRL0);
	cpu_ctrl1_saved = vmcs_read(CPU_EXEC_CTRL1);
	ar_saved = vmcs_read(GUEST_AR_SS);
	/* Turn off "unrestricted guest" vm-execution control */
	vmcs_write(CPU_EXEC_CTRL1, cpu_ctrl1_saved & ~CPU_URG);
	cs_rpl_bits = vmcs_read(GUEST_SEL_CS) & 0x3;
	sel_saved = vmcs_read(GUEST_SEL_SS);
	TEST_INVALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (~cs_rpl_bits & 0x3)));
	TEST_VALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (cs_rpl_bits & 0x3)));
	/* Make SS usable if it's unusable or vice-versa */
	if (ar_saved & GUEST_SEG_UNUSABLE_MASK)
		vmcs_write(GUEST_AR_SS, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	else
		vmcs_write(GUEST_AR_SS, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_INVALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (~cs_rpl_bits & 0x3)));
	TEST_VALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (cs_rpl_bits & 0x3)));

	/* Need a valid EPTP as the passing case fully enters the guest. */
	if (enable_unrestricted_guest(true))
		goto skip_ss_tests;

	TEST_VALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (~cs_rpl_bits & 0x3)));
	TEST_VALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (cs_rpl_bits & 0x3)));

	/* Make SS usable if it's unusable or vice-versa */
	if (vmcs_read(GUEST_AR_SS) & GUEST_SEG_UNUSABLE_MASK)
		vmcs_write(GUEST_AR_SS, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	else
		vmcs_write(GUEST_AR_SS, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_VALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (~cs_rpl_bits & 0x3)));
	TEST_VALID_SEG_SEL(GUEST_SEL_SS, ((sel_saved & ~0x3) | (cs_rpl_bits & 0x3)));
skip_ss_tests:

	vmcs_write(GUEST_AR_SS, ar_saved);
	vmcs_write(GUEST_SEL_SS, sel_saved);
	vmcs_write(CPU_EXEC_CTRL0, cpu_ctrl0_saved);
	vmcs_write(CPU_EXEC_CTRL1, cpu_ctrl1_saved);
}

#define	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(xfail, seg_base)			\
do {										\
	addr_saved = vmcs_read(seg_base);					\
	for (i = 32; i < 63; i = i + 4) {					\
		addr = addr_saved | 1ull << i;					\
		vmcs_write(seg_base, addr);					\
		test_guest_state("seg.BASE[63:32] != 0, usable = " xstr(xfail),	\
				 xfail, addr, xstr(seg_base));			\
	}									\
	vmcs_write(seg_base, addr_saved);					\
} while (0)

#define	TEST_SEGMENT_BASE_ADDR_CANONICAL(xfail, seg_base)		  \
do {									  \
	addr_saved = vmcs_read(seg_base);				  \
	vmcs_write(seg_base, NONCANONICAL);				  \
	test_guest_state("seg.BASE non-canonical, usable = " xstr(xfail), \
			 xfail, NONCANONICAL, xstr(seg_base));		  \
	vmcs_write(seg_base, addr_saved);				  \
} while (0)

/*
 * The following checks are done on the Base Address field of the Guest
 * Segment Registers on processors that support Intel 64 architecture:
 *    - TR, FS, GS : The address must be canonical.
 *    - LDTR : If LDTR is usable, the address must be canonical.
 *    - CS : Bits 63:32 of the address must be zero.
 *    - SS, DS, ES : If the register is usable, bits 63:32 of the address
 *	must be zero.
 *
 *  [Intel SDM]
 */
static void test_guest_segment_base_addr_fields(void)
{
	u64 addr_saved;
	u64 addr;
	u32 ar_saved;
	int i;

	/*
	 * The address of TR, FS, GS and LDTR must be canonical.
	 */
	TEST_SEGMENT_BASE_ADDR_CANONICAL(true, GUEST_BASE_TR);
	TEST_SEGMENT_BASE_ADDR_CANONICAL(true, GUEST_BASE_FS);
	TEST_SEGMENT_BASE_ADDR_CANONICAL(true, GUEST_BASE_GS);
	ar_saved = vmcs_read(GUEST_AR_LDTR);
	/* Make LDTR unusable */
	vmcs_write(GUEST_AR_LDTR, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_CANONICAL(false, GUEST_BASE_LDTR);
	/* Make LDTR usable */
	vmcs_write(GUEST_AR_LDTR, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_CANONICAL(true, GUEST_BASE_LDTR);

	vmcs_write(GUEST_AR_LDTR, ar_saved);

	/*
	 * Bits 63:32 in CS, SS, DS and ES base address must be zero
	 */
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(true, GUEST_BASE_CS);
	ar_saved = vmcs_read(GUEST_AR_SS);
	/* Make SS unusable */
	vmcs_write(GUEST_AR_SS, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(false, GUEST_BASE_SS);
	/* Make SS usable */
	vmcs_write(GUEST_AR_SS, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(true, GUEST_BASE_SS);
	vmcs_write(GUEST_AR_SS, ar_saved);

	ar_saved = vmcs_read(GUEST_AR_DS);
	/* Make DS unusable */
	vmcs_write(GUEST_AR_DS, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(false, GUEST_BASE_DS);
	/* Make DS usable */
	vmcs_write(GUEST_AR_DS, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(true, GUEST_BASE_DS);
	vmcs_write(GUEST_AR_DS, ar_saved);

	ar_saved = vmcs_read(GUEST_AR_ES);
	/* Make ES unusable */
	vmcs_write(GUEST_AR_ES, ar_saved | GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(false, GUEST_BASE_ES);
	/* Make ES usable */
	vmcs_write(GUEST_AR_ES, ar_saved & ~GUEST_SEG_UNUSABLE_MASK);
	TEST_SEGMENT_BASE_ADDR_UPPER_BITS(true, GUEST_BASE_ES);
	vmcs_write(GUEST_AR_ES, ar_saved);
}

/*
 * Check that the virtual CPU checks the VMX Guest State Area as
 * documented in the Intel SDM.
 */
static void vmx_guest_state_area_test(void)
{
	vmx_set_test_stage(1);
	test_set_guest(guest_state_test_main);

	/*
	 * The IA32_SYSENTER_ESP field and the IA32_SYSENTER_EIP field
	 * must each contain a canonical address.
	 */
	test_canonical(GUEST_SYSENTER_ESP, "GUEST_SYSENTER_ESP", false);
	test_canonical(GUEST_SYSENTER_EIP, "GUEST_SYSENTER_EIP", false);

	test_guest_dr7();
	test_load_guest_pat();
	test_guest_efer();
	test_load_guest_perf_global_ctrl();
	test_load_guest_bndcfgs();

	test_guest_segment_sel_fields();
	test_guest_segment_base_addr_fields();

	test_canonical(GUEST_BASE_GDTR, "GUEST_BASE_GDTR", false);
	test_canonical(GUEST_BASE_IDTR, "GUEST_BASE_IDTR", false);

	u32 guest_desc_limit_saved = vmcs_read(GUEST_LIMIT_GDTR);
	int i;
	for (i = 16; i <= 31; i++) {
		u32 tmp = guest_desc_limit_saved | (1ull << i);
		vmcs_write(GUEST_LIMIT_GDTR, tmp);
		test_guest_state("GDT.limit > 0xffff", true, tmp, "GUEST_LIMIT_GDTR");
	}
	vmcs_write(GUEST_LIMIT_GDTR, guest_desc_limit_saved);

	guest_desc_limit_saved = vmcs_read(GUEST_LIMIT_IDTR);
	for (i = 16; i <= 31; i++) {
		u32 tmp = guest_desc_limit_saved | (1ull << i);
		vmcs_write(GUEST_LIMIT_IDTR, tmp);
		test_guest_state("IDT.limit > 0xffff", true, tmp, "GUEST_LIMIT_IDTR");
	}
	vmcs_write(GUEST_LIMIT_IDTR, guest_desc_limit_saved);

	/*
	 * Let the guest finish execution
	 */
	vmx_set_test_stage(2);
	enter_guest();
}

extern void unrestricted_guest_main(void);
asm (".code32\n"
	"unrestricted_guest_main:\n"
	"vmcall\n"
	"nop\n"
	"mov $1, %edi\n"
	"call hypercall\n"
	".code64\n");

static void setup_unrestricted_guest(void)
{
	vmcs_write(GUEST_CR0, vmcs_read(GUEST_CR0) & ~(X86_CR0_PG));
	vmcs_write(ENT_CONTROLS, vmcs_read(ENT_CONTROLS) & ~ENT_GUEST_64);
	vmcs_write(GUEST_EFER, vmcs_read(GUEST_EFER) & ~EFER_LMA);
	vmcs_write(GUEST_RIP, virt_to_phys(unrestricted_guest_main));
}

static void unsetup_unrestricted_guest(void)
{
	vmcs_write(GUEST_CR0, vmcs_read(GUEST_CR0) | X86_CR0_PG);
	vmcs_write(ENT_CONTROLS, vmcs_read(ENT_CONTROLS) | ENT_GUEST_64);
	vmcs_write(GUEST_EFER, vmcs_read(GUEST_EFER) | EFER_LMA);
	vmcs_write(GUEST_RIP, (u64) phys_to_virt(vmcs_read(GUEST_RIP)));
	vmcs_write(GUEST_RSP, (u64) phys_to_virt(vmcs_read(GUEST_RSP)));
}

/*
 * If "unrestricted guest" secondary VM-execution control is set, guests
 * can run in unpaged protected mode.
 */
static void vmentry_unrestricted_guest_test(void)
{
	if (enable_unrestricted_guest(true)) {
		report_skip("%s: \"Unrestricted guest\" exec control not supported", __func__);
		return;
	}

	test_set_guest(unrestricted_guest_main);
	setup_unrestricted_guest();
	test_guest_state("Unrestricted guest test", false, CPU_URG, "CPU_URG");

	/*
	 * Let the guest finish execution as a regular guest
	 */
	unsetup_unrestricted_guest();
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) & ~CPU_URG);
	enter_guest();
}

static bool valid_vmcs_for_vmentry(void)
{
	struct vmcs *current_vmcs = NULL;

	if (vmcs_save(&current_vmcs))
		return false;

	return current_vmcs && !current_vmcs->hdr.shadow_vmcs;
}

static void try_vmentry_in_movss_shadow(void)
{
	u32 vm_inst_err;
	u32 flags;
	bool early_failure = false;
	u32 expected_flags = X86_EFLAGS_FIXED;
	bool valid_vmcs = valid_vmcs_for_vmentry();

	expected_flags |= valid_vmcs ? X86_EFLAGS_ZF : X86_EFLAGS_CF;

	/*
	 * Indirectly set VM_INST_ERR to 12 ("VMREAD/VMWRITE from/to
	 * unsupported VMCS component").
	 */
	vmcs_write(~0u, 0);

	__asm__ __volatile__ ("mov %[host_rsp], %%edx;"
			      "vmwrite %%rsp, %%rdx;"
			      "mov 0f, %%rax;"
			      "mov %[host_rip], %%edx;"
			      "vmwrite %%rax, %%rdx;"
			      "mov $-1, %%ah;"
			      "sahf;"
			      "mov %%ss, %%ax;"
			      "mov %%ax, %%ss;"
			      "vmlaunch;"
			      "mov $1, %[early_failure];"
			      "0: lahf;"
			      "movzbl %%ah, %[flags]"
			      : [early_failure] "+r" (early_failure),
				[flags] "=&a" (flags)
			      : [host_rsp] "i" (HOST_RSP),
				[host_rip] "i" (HOST_RIP)
			      : "rdx", "cc", "memory");
	vm_inst_err = vmcs_read(VMX_INST_ERROR);

	report(early_failure, "Early VM-entry failure");
	report(flags == expected_flags, "RFLAGS[8:0] is %x (actual %x)",
	       expected_flags, flags);
	if (valid_vmcs)
		report(vm_inst_err == VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS,
		       "VM-instruction error is %d (actual %d)",
		       VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS, vm_inst_err);
}

static void vmentry_movss_shadow_test(void)
{
	struct vmcs *orig_vmcs;

	TEST_ASSERT(!vmcs_save(&orig_vmcs));

	/*
	 * Set the launched flag on the current VMCS to verify the correct
	 * error priority, below.
	 */
	test_set_guest(v2_null_test_guest);
	enter_guest();

	/*
	 * With bit 1 of the guest's RFLAGS clear, VM-entry should
	 * fail due to invalid guest state (if we make it that far).
	 */
	vmcs_write(GUEST_RFLAGS, 0);

	/*
	 * "VM entry with events blocked by MOV SS" takes precedence over
	 * "VMLAUNCH with non-clear VMCS."
	 */
	report_prefix_push("valid current-VMCS");
	try_vmentry_in_movss_shadow();
	report_prefix_pop();

	/*
	 * VMfailInvalid takes precedence over "VM entry with events
	 * blocked by MOV SS."
	 */
	TEST_ASSERT(!vmcs_clear(orig_vmcs));
	report_prefix_push("no current-VMCS");
	try_vmentry_in_movss_shadow();
	report_prefix_pop();

	TEST_ASSERT(!make_vmcs_current(orig_vmcs));
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED);
}

static void vmx_ldtr_test_guest(void)
{
	u16 ldtr = sldt();

	report(ldtr == NP_SEL, "Expected %x for L2 LDTR selector (got %x)",
	       NP_SEL, ldtr);
}

/*
 * Ensure that the L1 LDTR is set to 0 on VM-exit.
 */
static void vmx_ldtr_test(void)
{
	const u8 ldt_ar = 0x82; /* Present LDT */
	u16 sel = FIRST_SPARE_SEL;

	/* Set up a non-zero L1 LDTR prior to VM-entry. */
	set_gdt_entry(sel, 0, 0, ldt_ar, 0);
	lldt(sel);

	test_set_guest(vmx_ldtr_test_guest);
	/*
	 * Set up a different LDTR for L2. The actual GDT contents are
	 * irrelevant, since we stuff the hidden descriptor state
	 * straight into the VMCS rather than reading it from the GDT.
	 */
	vmcs_write(GUEST_SEL_LDTR, NP_SEL);
	vmcs_write(GUEST_AR_LDTR, ldt_ar);
	enter_guest();

	/*
	 * VM-exit should clear LDTR (and make it unusable, but we
	 * won't verify that here).
	 */
	sel = sldt();
	report(!sel, "Expected 0 for L1 LDTR selector (got %x)", sel);
}

static void vmx_single_vmcall_guest(void)
{
	vmcall();
}

static void vmx_cr_load_test(void)
{
	unsigned long cr3, cr4, orig_cr3, orig_cr4;
	u32 ctrls[2] = {0};
	pgd_t *pml5;

	orig_cr4 = read_cr4();
	orig_cr3 = read_cr3();

	if (!this_cpu_has(X86_FEATURE_PCID)) {
		report_skip("%s : PCID not detected", __func__);
		return;
	}
	if (!this_cpu_has(X86_FEATURE_MCE)) {
		report_skip("%s : MCE not detected", __func__);
		return;
	}

	TEST_ASSERT(!(orig_cr3 & X86_CR3_PCID_MASK));

	/* Enable PCID for L1. */
	cr4 = orig_cr4 | X86_CR4_PCIDE;
	cr3 = orig_cr3 | 0x1;
	TEST_ASSERT(!write_cr4_safe(cr4));
	write_cr3(cr3);

	test_set_guest(vmx_single_vmcall_guest);
	vmcs_write(HOST_CR4, cr4);
	vmcs_write(HOST_CR3, cr3);
	enter_guest();

	/*
	 * No exception is expected.
	 *
	 * NB. KVM loads the last guest write to CR4 into CR4 read
	 *     shadow. In order to trigger an exit to KVM, we can toggle a
	 *     bit that is owned by KVM. We use CR4.MCE, which shall
	 *     have no side effect because normally no guest MCE (e.g., as the
	 *     result of bad memory) would happen during this test.
	 */
	TEST_ASSERT(!write_cr4_safe(cr4 ^ X86_CR4_MCE));

	/* Cleanup L1 state. */
	write_cr3(orig_cr3);
	TEST_ASSERT(!write_cr4_safe(orig_cr4));

	if (!this_cpu_has(X86_FEATURE_LA57))
		goto done;

	/*
	 * Allocate a full page for PML5 to guarantee alignment, though only
	 * the first entry needs to be filled (the test's virtual addresses
	 * most definitely do not have any of bits 56:48 set).
	 */
	pml5 = alloc_page();
	*pml5 = orig_cr3 | PT_PRESENT_MASK | PT_WRITABLE_MASK;

	/*
	 * Transition to/from 5-level paging in the host via VM-Exit.  CR4.LA57
	 * can't be toggled while long is active via MOV CR4, but there are no
	 * such restrictions on VM-Exit.
	 */
lol_5level:
	vmcs_write(HOST_CR4, orig_cr4 | X86_CR4_LA57);
	vmcs_write(HOST_CR3, virt_to_phys(pml5));
	enter_guest();

	/*
	 * VMREAD with a memory operand to verify KVM detects the LA57 change,
	 * e.g. uses the correct guest root level in gva_to_gpa().
	 */
	TEST_ASSERT(vmcs_readm(HOST_CR3) == virt_to_phys(pml5));
	TEST_ASSERT(vmcs_readm(HOST_CR4) == (orig_cr4 | X86_CR4_LA57));

	vmcs_write(HOST_CR4, orig_cr4);
	vmcs_write(HOST_CR3, orig_cr3);
	enter_guest();

	TEST_ASSERT(vmcs_readm(HOST_CR3) == orig_cr3);
	TEST_ASSERT(vmcs_readm(HOST_CR4) == orig_cr4);

	/*
	 * And now do the same LA57 shenanigans with EPT enabled.  KVM uses
	 * two separate MMUs when L1 uses TDP, whereas the above shadow paging
	 * version shares an MMU between L1 and L2.
	 *
	 * If the saved execution controls are non-zero then the EPT version
	 * has already run.  In that case, restore the old controls.  If EPT
	 * setup fails, e.g. EPT isn't supported, fall through and finish up.
	 */
	if (ctrls[0]) {
		vmcs_write(CPU_EXEC_CTRL0, ctrls[0]);
		vmcs_write(CPU_EXEC_CTRL1, ctrls[1]);
	} else if (!setup_ept(false)) {
		ctrls[0] = vmcs_read(CPU_EXEC_CTRL0);
		ctrls[1]  = vmcs_read(CPU_EXEC_CTRL1);
		goto lol_5level;
	}

	free_page(pml5);

done:
	skip_exit_vmcall();
	enter_guest();
}

static void vmx_cr4_osxsave_test_guest(void)
{
	write_cr4(read_cr4() & ~X86_CR4_OSXSAVE);
}

/*
 * Ensure that kvm recalculates the L1 guest's CPUID.01H:ECX.OSXSAVE
 * after VM-exit from an L2 guest that sets CR4.OSXSAVE to a different
 * value than in L1.
 */
static void vmx_cr4_osxsave_test(void)
{
	if (!this_cpu_has(X86_FEATURE_XSAVE)) {
		report_skip("%s : XSAVE not detected", __func__);
		return;
	}

	if (!(read_cr4() & X86_CR4_OSXSAVE)) {
		unsigned long cr4 = read_cr4() | X86_CR4_OSXSAVE;

		write_cr4(cr4);
		vmcs_write(GUEST_CR4, cr4);
		vmcs_write(HOST_CR4, cr4);
	}

	TEST_ASSERT(this_cpu_has(X86_FEATURE_OSXSAVE));

	test_set_guest(vmx_cr4_osxsave_test_guest);
	enter_guest();

	TEST_ASSERT(this_cpu_has(X86_FEATURE_OSXSAVE));
}

static void vmx_nm_test_guest(void)
{
	write_cr0(read_cr0() | X86_CR0_TS);
	asm volatile("fnop");
}

static void check_nm_exit(const char *test)
{
	u32 reason = vmcs_read(EXI_REASON);
	u32 intr_info = vmcs_read(EXI_INTR_INFO);
	const u32 expected = INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION |
		NM_VECTOR;

	report(reason == VMX_EXC_NMI && intr_info == expected, "%s", test);
}

/*
 * This test checks that:
 *
 * (a) If L2 launches with CR0.TS clear, but later sets CR0.TS, then
 *     a subsequent #NM VM-exit is reflected to L1.
 *
 * (b) If L2 launches with CR0.TS clear and CR0.EM set, then a
 *     subsequent #NM VM-exit is reflected to L1.
 */
static void vmx_nm_test(void)
{
	unsigned long cr0 = read_cr0();

	test_set_guest(vmx_nm_test_guest);

	/*
	 * L1 wants to intercept #NM exceptions encountered in L2.
	 */
	vmcs_write(EXC_BITMAP, 1 << NM_VECTOR);

	/*
	 * Launch L2 with CR0.TS clear, but don't claim host ownership of
	 * any CR0 bits. L2 will set CR0.TS and then try to execute fnop,
	 * which will raise #NM. L0 should reflect the #NM VM-exit to L1.
	 */
	vmcs_write(CR0_MASK, 0);
	vmcs_write(GUEST_CR0, cr0 & ~X86_CR0_TS);
	enter_guest();
	check_nm_exit("fnop with CR0.TS set in L2 triggers #NM VM-exit to L1");

	/*
	 * Re-enter L2 at the fnop instruction, with CR0.TS clear but
	 * CR0.EM set. The fnop will still raise #NM, and L0 should
	 * reflect the #NM VM-exit to L1.
	 */
	vmcs_write(GUEST_CR0, (cr0 & ~X86_CR0_TS) | X86_CR0_EM);
	enter_guest();
	check_nm_exit("fnop with CR0.EM set in L2 triggers #NM VM-exit to L1");

	/*
	 * Re-enter L2 at the fnop instruction, with both CR0.TS and
	 * CR0.EM clear. There will be no #NM, and the L2 guest should
	 * exit normally.
	 */
	vmcs_write(GUEST_CR0, cr0 & ~(X86_CR0_TS | X86_CR0_EM));
	enter_guest();
}

bool vmx_pending_event_ipi_fired;
static void vmx_pending_event_ipi_isr(isr_regs_t *regs)
{
	vmx_pending_event_ipi_fired = true;
	eoi();
}

bool vmx_pending_event_guest_run;
static void vmx_pending_event_guest(void)
{
	vmcall();
	vmx_pending_event_guest_run = true;
}

static void vmx_pending_event_test_core(bool guest_hlt)
{
	int ipi_vector = 0xf1;

	vmx_pending_event_ipi_fired = false;
	handle_irq(ipi_vector, vmx_pending_event_ipi_isr);

	vmx_pending_event_guest_run = false;
	test_set_guest(vmx_pending_event_guest);

	vmcs_set_bits(PIN_CONTROLS, PIN_EXTINT);

	enter_guest();
	skip_exit_vmcall();

	if (guest_hlt)
		vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);

	irq_disable();
	apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
				   APIC_DM_FIXED | ipi_vector,
				   0);

	enter_guest();

	assert_exit_reason(VMX_EXTINT);
	report(!vmx_pending_event_guest_run,
	       "Guest did not run before host received IPI");

	irq_enable();
	asm volatile ("nop");
	irq_disable();
	report(vmx_pending_event_ipi_fired,
	       "Got pending interrupt after IRQ enabled");

	if (guest_hlt)
		vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);

	enter_guest();
	report(vmx_pending_event_guest_run,
	       "Guest finished running when no interrupt");
}

static void vmx_pending_event_test(void)
{
	vmx_pending_event_test_core(false);
}

static void vmx_pending_event_hlt_test(void)
{
	vmx_pending_event_test_core(true);
}

static int vmx_window_test_db_count;

static void vmx_window_test_db_handler(struct ex_regs *regs)
{
	vmx_window_test_db_count++;
}

static void vmx_nmi_window_test_guest(void)
{
	handle_exception(DB_VECTOR, vmx_window_test_db_handler);

	asm volatile("vmcall\n\t"
		     "nop\n\t");

	handle_exception(DB_VECTOR, NULL);
}

static void verify_nmi_window_exit(u64 rip)
{
	u32 exit_reason = vmcs_read(EXI_REASON);

	report(exit_reason == VMX_NMI_WINDOW,
	       "Exit reason (%d) is 'NMI window'", exit_reason);
	report(vmcs_read(GUEST_RIP) == rip, "RIP (%#lx) is %#lx",
	       vmcs_read(GUEST_RIP), rip);
	vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
}

static void vmx_nmi_window_test(void)
{
	u64 nop_addr;
	void *db_fault_addr = get_idt_addr(&boot_idt[DB_VECTOR]);

	if (!(ctrl_pin_rev.clr & PIN_VIRT_NMI)) {
		report_skip("%s : \"Virtual NMIs\" exec control not supported", __func__);
		return;
	}

	if (!(ctrl_cpu_rev[0].clr & CPU_NMI_WINDOW)) {
		report_skip("%s : \"NMI-window exiting\" exec control not supported", __func__);
		return;
	}

	vmx_window_test_db_count = 0;

	report_prefix_push("NMI-window");
	test_set_guest(vmx_nmi_window_test_guest);
	vmcs_set_bits(PIN_CONTROLS, PIN_VIRT_NMI);
	enter_guest();
	skip_exit_vmcall();
	nop_addr = vmcs_read(GUEST_RIP);

	/*
	 * Ask for "NMI-window exiting," and expect an immediate VM-exit.
	 * RIP will not advance.
	 */
	report_prefix_push("active, no blocking");
	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_NMI_WINDOW);
	enter_guest();
	verify_nmi_window_exit(nop_addr);
	report_prefix_pop();

	/*
	 * Ask for "NMI-window exiting" in a MOV-SS shadow, and expect
	 * a VM-exit on the next instruction after the nop. (The nop
	 * is one byte.)
	 */
	report_prefix_push("active, blocking by MOV-SS");
	vmcs_write(GUEST_INTR_STATE, GUEST_INTR_STATE_MOVSS);
	enter_guest();
	verify_nmi_window_exit(nop_addr + 1);
	report_prefix_pop();

	/*
	 * Ask for "NMI-window exiting" (with event injection), and
	 * expect a VM-exit after the event is injected. (RIP should
	 * be at the address specified in the IDT entry for #DB.)
	 */
	report_prefix_push("active, no blocking, injecting #DB");
	vmcs_write(ENT_INTR_INFO,
		   INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION | DB_VECTOR);
	enter_guest();
	verify_nmi_window_exit((u64)db_fault_addr);
	report_prefix_pop();

	/*
	 * Ask for "NMI-window exiting" with NMI blocking, and expect
	 * a VM-exit after the next IRET (i.e. after the #DB handler
	 * returns). So, RIP should be back at one byte past the nop.
	 */
	report_prefix_push("active, blocking by NMI");
	vmcs_write(GUEST_INTR_STATE, GUEST_INTR_STATE_NMI);
	enter_guest();
	verify_nmi_window_exit(nop_addr + 1);
	report(vmx_window_test_db_count == 1,
	       "#DB handler executed once (actual %d times)",
	       vmx_window_test_db_count);
	report_prefix_pop();

	if (!(rdmsr(MSR_IA32_VMX_MISC) & (1 << 6))) {
		report_skip("CPU does not support activity state HLT.");
	} else {
		/*
		 * Ask for "NMI-window exiting" when entering activity
		 * state HLT, and expect an immediate VM-exit. RIP is
		 * still one byte past the nop.
		 */
		report_prefix_push("halted, no blocking");
		vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
		enter_guest();
		verify_nmi_window_exit(nop_addr + 1);
		report_prefix_pop();

		/*
		 * Ask for "NMI-window exiting" when entering activity
		 * state HLT (with event injection), and expect a
		 * VM-exit after the event is injected. (RIP should be
		 * at the address specified in the IDT entry for #DB.)
		 */
		report_prefix_push("halted, no blocking, injecting #DB");
		vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
		vmcs_write(ENT_INTR_INFO,
			   INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION |
			   DB_VECTOR);
		enter_guest();
		verify_nmi_window_exit((u64)db_fault_addr);
		report_prefix_pop();
	}

	vmcs_clear_bits(CPU_EXEC_CTRL0, CPU_NMI_WINDOW);
	enter_guest();
	report_prefix_pop();
}

static void vmx_intr_window_test_guest(void)
{
	handle_exception(DB_VECTOR, vmx_window_test_db_handler);

	/*
	 * The two consecutive STIs are to ensure that only the first
	 * one has a shadow. Note that NOP and STI are one byte
	 * instructions.
	 */
	asm volatile("vmcall\n\t"
		     "nop\n\t"
		     "sti\n\t"
		     "sti\n\t");

	handle_exception(DB_VECTOR, NULL);
}

static void verify_intr_window_exit(u64 rip)
{
	u32 exit_reason = vmcs_read(EXI_REASON);

	report(exit_reason == VMX_INTR_WINDOW,
	       "Exit reason (%d) is 'interrupt window'", exit_reason);
	report(vmcs_read(GUEST_RIP) == rip, "RIP (%#lx) is %#lx",
	       vmcs_read(GUEST_RIP), rip);
	vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
}

static void vmx_intr_window_test(void)
{
	u64 vmcall_addr;
	u64 nop_addr;
	unsigned int orig_db_gate_type;
	void *db_fault_addr = get_idt_addr(&boot_idt[DB_VECTOR]);

	if (!(ctrl_cpu_rev[0].clr & CPU_INTR_WINDOW)) {
		report_skip("%s : \"Interrupt-window exiting\" exec control not supported", __func__);
		return;
	}

	/*
	 * Change the IDT entry for #DB from interrupt gate to trap gate,
	 * so that it won't clear RFLAGS.IF. We don't want interrupts to
	 * be disabled after vectoring a #DB.
	 */
	orig_db_gate_type = boot_idt[DB_VECTOR].type;
	boot_idt[DB_VECTOR].type = 15;

	report_prefix_push("interrupt-window");
	test_set_guest(vmx_intr_window_test_guest);
	enter_guest();
	assert_exit_reason(VMX_VMCALL);
	vmcall_addr = vmcs_read(GUEST_RIP);

	/*
	 * Ask for "interrupt-window exiting" with RFLAGS.IF set and
	 * no blocking; expect an immediate VM-exit. Note that we have
	 * not advanced past the vmcall instruction yet, so RIP should
	 * point to the vmcall instruction.
	 */
	report_prefix_push("active, no blocking, RFLAGS.IF=1");
	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_INTR_WINDOW);
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED | X86_EFLAGS_IF);
	enter_guest();
	verify_intr_window_exit(vmcall_addr);
	report_prefix_pop();

	/*
	 * Ask for "interrupt-window exiting" (with event injection)
	 * with RFLAGS.IF set and no blocking; expect a VM-exit after
	 * the event is injected. That is, RIP should should be at the
	 * address specified in the IDT entry for #DB.
	 */
	report_prefix_push("active, no blocking, RFLAGS.IF=1, injecting #DB");
	vmcs_write(ENT_INTR_INFO,
		   INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION | DB_VECTOR);
	vmcall_addr = vmcs_read(GUEST_RIP);
	enter_guest();
	verify_intr_window_exit((u64)db_fault_addr);
	report_prefix_pop();

	/*
	 * Let the L2 guest run through the IRET, back to the VMCALL.
	 * We have to clear the "interrupt-window exiting"
	 * VM-execution control, or it would just keep causing
	 * VM-exits. Then, advance past the VMCALL and set the
	 * "interrupt-window exiting" VM-execution control again.
	 */
	vmcs_clear_bits(CPU_EXEC_CTRL0, CPU_INTR_WINDOW);
	enter_guest();
	skip_exit_vmcall();
	nop_addr = vmcs_read(GUEST_RIP);
	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_INTR_WINDOW);

	/*
	 * Ask for "interrupt-window exiting" in a MOV-SS shadow with
	 * RFLAGS.IF set, and expect a VM-exit on the next
	 * instruction. (NOP is one byte.)
	 */
	report_prefix_push("active, blocking by MOV-SS, RFLAGS.IF=1");
	vmcs_write(GUEST_INTR_STATE, GUEST_INTR_STATE_MOVSS);
	enter_guest();
	verify_intr_window_exit(nop_addr + 1);
	report_prefix_pop();

	/*
	 * Back up to the NOP and ask for "interrupt-window exiting"
	 * in an STI shadow with RFLAGS.IF set, and expect a VM-exit
	 * on the next instruction. (NOP is one byte.)
	 */
	report_prefix_push("active, blocking by STI, RFLAGS.IF=1");
	vmcs_write(GUEST_RIP, nop_addr);
	vmcs_write(GUEST_INTR_STATE, GUEST_INTR_STATE_STI);
	enter_guest();
	verify_intr_window_exit(nop_addr + 1);
	report_prefix_pop();

	/*
	 * Ask for "interrupt-window exiting" with RFLAGS.IF clear,
	 * and expect a VM-exit on the instruction following the STI
	 * shadow. Only the first STI (which is one byte past the NOP)
	 * should have a shadow. The second STI (which is two bytes
	 * past the NOP) has no shadow. Therefore, the interrupt
	 * window opens at three bytes past the NOP.
	 */
	report_prefix_push("active, RFLAGS.IF = 0");
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED);
	enter_guest();
	verify_intr_window_exit(nop_addr + 3);
	report_prefix_pop();

	if (!(rdmsr(MSR_IA32_VMX_MISC) & (1 << 6))) {
		report_skip("CPU does not support activity state HLT.");
	} else {
		/*
		 * Ask for "interrupt-window exiting" when entering
		 * activity state HLT, and expect an immediate
		 * VM-exit. RIP is still three bytes past the nop.
		 */
		report_prefix_push("halted, no blocking");
		vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
		enter_guest();
		verify_intr_window_exit(nop_addr + 3);
		report_prefix_pop();

		/*
		 * Ask for "interrupt-window exiting" when entering
		 * activity state HLT (with event injection), and
		 * expect a VM-exit after the event is injected. That
		 * is, RIP should should be at the address specified
		 * in the IDT entry for #DB.
		 */
		report_prefix_push("halted, no blocking, injecting #DB");
		vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
		vmcs_write(ENT_INTR_INFO,
			   INTR_INFO_VALID_MASK | INTR_TYPE_HARD_EXCEPTION |
			   DB_VECTOR);
		enter_guest();
		verify_intr_window_exit((u64)db_fault_addr);
		report_prefix_pop();
	}

	boot_idt[DB_VECTOR].type = orig_db_gate_type;
	vmcs_clear_bits(CPU_EXEC_CTRL0, CPU_INTR_WINDOW);
	enter_guest();
	report_prefix_pop();
}

#define GUEST_TSC_OFFSET (1u << 30)

static u64 guest_tsc;

static void vmx_store_tsc_test_guest(void)
{
	guest_tsc = rdtsc();
}

/*
 * This test ensures that when IA32_TSC is in the VM-exit MSR-store
 * list, the value saved is not subject to the TSC offset that is
 * applied to RDTSC/RDTSCP/RDMSR(IA32_TSC) in guest execution.
 */
static void vmx_store_tsc_test(void)
{
	struct vmx_msr_entry msr_entry = { .index = MSR_IA32_TSC };
	u64 low, high;

	if (!(ctrl_cpu_rev[0].clr & CPU_USE_TSC_OFFSET)) {
		report_skip("%s : \"Use TSC offsetting\" exec control not supported", __func__);
		return;
	}

	test_set_guest(vmx_store_tsc_test_guest);

	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_USE_TSC_OFFSET);
	vmcs_write(EXI_MSR_ST_CNT, 1);
	vmcs_write(EXIT_MSR_ST_ADDR, virt_to_phys(&msr_entry));
	vmcs_write(TSC_OFFSET, GUEST_TSC_OFFSET);

	low = rdtsc();
	enter_guest();
	high = rdtsc();

	report(low + GUEST_TSC_OFFSET <= guest_tsc &&
	       guest_tsc <= high + GUEST_TSC_OFFSET,
	       "RDTSC value in the guest (%lu) is in range [%lu, %lu]",
	       guest_tsc, low + GUEST_TSC_OFFSET, high + GUEST_TSC_OFFSET);
	report(low <= msr_entry.value && msr_entry.value <= high,
	       "IA32_TSC value saved in the VM-exit MSR-store list (%lu) is in range [%lu, %lu]",
	       msr_entry.value, low, high);
}

static void vmx_preemption_timer_zero_test_db_handler(struct ex_regs *regs)
{
}

static void vmx_preemption_timer_zero_test_guest(void)
{
	while (vmx_get_test_stage() < 3)
		vmcall();
}

static void vmx_preemption_timer_zero_activate_preemption_timer(void)
{
	vmcs_set_bits(PIN_CONTROLS, PIN_PREEMPT);
	vmcs_write(PREEMPT_TIMER_VALUE, 0);
}

static void vmx_preemption_timer_zero_advance_past_vmcall(void)
{
	vmcs_clear_bits(PIN_CONTROLS, PIN_PREEMPT);
	enter_guest();
	skip_exit_vmcall();
}

static void vmx_preemption_timer_zero_inject_db(bool intercept_db)
{
	vmx_preemption_timer_zero_activate_preemption_timer();
	vmcs_write(ENT_INTR_INFO, INTR_INFO_VALID_MASK |
		   INTR_TYPE_HARD_EXCEPTION | DB_VECTOR);
	vmcs_write(EXC_BITMAP, intercept_db ? 1 << DB_VECTOR : 0);
	enter_guest();
}

static void vmx_preemption_timer_zero_set_pending_dbg(u32 exception_bitmap)
{
	vmx_preemption_timer_zero_activate_preemption_timer();
	vmcs_write(GUEST_PENDING_DEBUG, PENDING_DBG_TRAP | DR6_TRAP1);
	vmcs_write(EXC_BITMAP, exception_bitmap);
	enter_guest();
}

static void vmx_preemption_timer_zero_expect_preempt_at_rip(u64 expected_rip)
{
	u32 reason = (u32)vmcs_read(EXI_REASON);
	u64 guest_rip = vmcs_read(GUEST_RIP);

	report(reason == VMX_PREEMPT && guest_rip == expected_rip,
	       "Exit reason is 0x%x (expected 0x%x) and guest RIP is %lx (0x%lx expected).",
	       reason, VMX_PREEMPT, guest_rip, expected_rip);
}

/*
 * This test ensures that when the VMX preemption timer is zero at
 * VM-entry, a VM-exit occurs after any event injection and after any
 * pending debug exceptions are raised, but before execution of any
 * guest instructions.
 */
static void vmx_preemption_timer_zero_test(void)
{
	u64 db_fault_address = (u64)get_idt_addr(&boot_idt[DB_VECTOR]);
	handler old_db;
	u32 reason;

	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		report_skip("%s : \"Activate VMX-preemption timer\" pin control not supported", __func__);
		return;
	}

	/*
	 * Install a custom #DB handler that doesn't abort.
	 */
	old_db = handle_exception(DB_VECTOR,
				  vmx_preemption_timer_zero_test_db_handler);

	test_set_guest(vmx_preemption_timer_zero_test_guest);

	/*
	 * VMX-preemption timer should fire after event injection.
	 */
	vmx_set_test_stage(0);
	vmx_preemption_timer_zero_inject_db(0);
	vmx_preemption_timer_zero_expect_preempt_at_rip(db_fault_address);
	vmx_preemption_timer_zero_advance_past_vmcall();

	/*
	 * VMX-preemption timer should fire after event injection.
	 * Exception bitmap is irrelevant, since you can't intercept
	 * an event that you injected.
	 */
	vmx_set_test_stage(1);
	vmx_preemption_timer_zero_inject_db(true);
	vmx_preemption_timer_zero_expect_preempt_at_rip(db_fault_address);
	vmx_preemption_timer_zero_advance_past_vmcall();

	/*
	 * VMX-preemption timer should fire after pending debug exceptions
	 * have delivered a #DB trap.
	 */
	vmx_set_test_stage(2);
	vmx_preemption_timer_zero_set_pending_dbg(0);
	vmx_preemption_timer_zero_expect_preempt_at_rip(db_fault_address);
	vmx_preemption_timer_zero_advance_past_vmcall();

	/*
	 * VMX-preemption timer would fire after pending debug exceptions
	 * have delivered a #DB trap, but in this case, the #DB trap is
	 * intercepted.
	 */
	vmx_set_test_stage(3);
	vmx_preemption_timer_zero_set_pending_dbg(1 << DB_VECTOR);
	reason = (u32)vmcs_read(EXI_REASON);
	report(reason == VMX_EXC_NMI, "Exit reason is 0x%x (expected 0x%x)",
	       reason, VMX_EXC_NMI);

	vmcs_clear_bits(PIN_CONTROLS, PIN_PREEMPT);
	enter_guest();

	handle_exception(DB_VECTOR, old_db);
}

static u64 vmx_preemption_timer_tf_test_prev_rip;

static void vmx_preemption_timer_tf_test_db_handler(struct ex_regs *regs)
{
	extern char vmx_preemption_timer_tf_test_endloop;

	if (vmx_get_test_stage() == 2) {
		/*
		 * Stage 2 means that we're done, one way or another.
		 * Arrange for the iret to drop us out of the wbinvd
		 * loop and stop single-stepping.
		 */
		regs->rip = (u64)&vmx_preemption_timer_tf_test_endloop;
		regs->rflags &= ~X86_EFLAGS_TF;
	} else if (regs->rip == vmx_preemption_timer_tf_test_prev_rip) {
		/*
		 * The RIP should alternate between the wbinvd and the
		 * jmp instruction in the code below. If we ever see
		 * the same instruction twice in a row, that means a
		 * single-step trap has been dropped. Let the
		 * hypervisor know about the failure by executing a
		 * VMCALL.
		 */
		vmcall();
	}
	vmx_preemption_timer_tf_test_prev_rip = regs->rip;
}

static void vmx_preemption_timer_tf_test_guest(void)
{
	/*
	 * The hypervisor doesn't intercept WBINVD, so the loop below
	 * shouldn't be a problem--it's just two instructions
	 * executing in VMX non-root mode. However, when the
	 * hypervisor is running in a virtual environment, the parent
	 * hypervisor might intercept WBINVD and emulate it. If the
	 * parent hypervisor is broken, the single-step trap after the
	 * WBINVD might be lost.
	 */
	asm volatile("vmcall\n\t"
		     "0: wbinvd\n\t"
		     "1: jmp 0b\n\t"
		     "vmx_preemption_timer_tf_test_endloop:");
}

/*
 * Ensure that the delivery of a "VMX-preemption timer expired"
 * VM-exit doesn't disrupt single-stepping in the guest. Note that
 * passing this test doesn't ensure correctness, because the test will
 * only fail if the VMX-preemtion timer fires at the right time (or
 * the wrong time, as it were).
 */
static void vmx_preemption_timer_tf_test(void)
{
	handler old_db;
	u32 reason;
	int i;

	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		report_skip("%s : \"Activate VMX-preemption timer\" pin control not supported", __func__);
		return;
	}

	old_db = handle_exception(DB_VECTOR,
				  vmx_preemption_timer_tf_test_db_handler);

	test_set_guest(vmx_preemption_timer_tf_test_guest);

	enter_guest();
	skip_exit_vmcall();

	vmx_set_test_stage(1);
	vmcs_set_bits(PIN_CONTROLS, PIN_PREEMPT);
	vmcs_write(PREEMPT_TIMER_VALUE, 50000);
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED | X86_EFLAGS_TF);

	/*
	 * The only exit we should see is "VMX-preemption timer
	 * expired."  If we get a VMCALL exit, that means the #DB
	 * handler has detected a missing single-step trap. It doesn't
	 * matter where the guest RIP is when the VMX-preemption timer
	 * expires (whether it's in the WBINVD loop or in the #DB
	 * handler)--a single-step trap should never be discarded.
	 */
	for (i = 0; i < 10000; i++) {
		enter_guest();
		reason = (u32)vmcs_read(EXI_REASON);
		if (reason == VMX_PREEMPT)
			continue;
		TEST_ASSERT(reason == VMX_VMCALL);
		skip_exit_insn();
		break;
	}

	report(reason == VMX_PREEMPT, "No single-step traps skipped");

	vmx_set_test_stage(2);
	vmcs_clear_bits(PIN_CONTROLS, PIN_PREEMPT);
	enter_guest();

	handle_exception(DB_VECTOR, old_db);
}

#define VMX_PREEMPTION_TIMER_EXPIRY_CYCLES 1000000

static u64 vmx_preemption_timer_expiry_start;
static u64 vmx_preemption_timer_expiry_finish;

static void vmx_preemption_timer_expiry_test_guest(void)
{
	vmcall();
	vmx_preemption_timer_expiry_start = fenced_rdtsc();

	while (vmx_get_test_stage() == 0)
		vmx_preemption_timer_expiry_finish = fenced_rdtsc();
}

/*
 * Test that the VMX-preemption timer is not excessively delayed.
 *
 * Per the SDM, volume 3, VM-entry starts the VMX-preemption timer
 * with the unsigned value in the VMX-preemption timer-value field,
 * and the VMX-preemption timer counts down by 1 every time bit X in
 * the TSC changes due to a TSC increment (where X is
 * IA32_VMX_MISC[4:0]). If the timer counts down to zero in any state
 * other than the wait-for-SIPI state, the logical processor
 * transitions to the C0 C-state and causes a VM-exit.
 *
 * The guest code above reads the starting TSC after VM-entry. At this
 * point, the VMX-preemption timer has already been activated. Next,
 * the guest code reads the current TSC in a loop, storing the value
 * read to memory.
 *
 * If the RDTSC in the loop reads a value past the VMX-preemption
 * timer deadline, then the VMX-preemption timer VM-exit must be
 * delivered before the next instruction retires. Even if a higher
 * priority SMI is delivered first, the VMX-preemption timer VM-exit
 * must be delivered before the next instruction retires. Hence, a TSC
 * value past the VMX-preemption timer deadline might be read, but it
 * cannot be stored. If a TSC value past the deadline *is* stored,
 * then the architectural specification has been violated.
 */
static void vmx_preemption_timer_expiry_test(void)
{
	u32 preemption_timer_value;
	union vmx_misc misc;
	u64 tsc_deadline;
	u32 reason;

	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		report_skip("%s : \"Activate VMX-preemption timer\" pin control not supported", __func__);
		return;
	}

	test_set_guest(vmx_preemption_timer_expiry_test_guest);

	enter_guest();
	skip_exit_vmcall();

	misc.val = rdmsr(MSR_IA32_VMX_MISC);
	preemption_timer_value =
		VMX_PREEMPTION_TIMER_EXPIRY_CYCLES >> misc.pt_bit;

	vmcs_set_bits(PIN_CONTROLS, PIN_PREEMPT);
	vmcs_write(PREEMPT_TIMER_VALUE, preemption_timer_value);
	vmx_set_test_stage(0);

	enter_guest();
	reason = (u32)vmcs_read(EXI_REASON);
	TEST_ASSERT(reason == VMX_PREEMPT);

	tsc_deadline = ((vmx_preemption_timer_expiry_start >> misc.pt_bit) <<
			misc.pt_bit) + (preemption_timer_value << misc.pt_bit);

	report(vmx_preemption_timer_expiry_finish < tsc_deadline,
	       "Last stored guest TSC (%lu) < TSC deadline (%lu)",
	       vmx_preemption_timer_expiry_finish, tsc_deadline);

	vmcs_clear_bits(PIN_CONTROLS, PIN_PREEMPT);
	vmx_set_test_stage(1);
	enter_guest();
}

static void vmx_db_test_guest(void)
{
	/*
	 * For a hardware generated single-step #DB.
	 */
	asm volatile("vmcall;"
		     "nop;"
		     ".Lpost_nop:");
	/*
	 * ...in a MOVSS shadow, with pending debug exceptions.
	 */
	asm volatile("vmcall;"
		     "nop;"
		     ".Lpost_movss_nop:");
	/*
	 * For an L0 synthesized single-step #DB. (L0 intercepts WBINVD and
	 * emulates it in software.)
	 */
	asm volatile("vmcall;"
		     "wbinvd;"
		     ".Lpost_wbinvd:");
	/*
	 * ...in a MOVSS shadow, with pending debug exceptions.
	 */
	asm volatile("vmcall;"
		     "wbinvd;"
		     ".Lpost_movss_wbinvd:");
	/*
	 * For a hardware generated single-step #DB in a transactional region.
	 */
	asm volatile("vmcall;"
		     ".Lxbegin: xbegin .Lskip_rtm;"
		     "xend;"
		     ".Lskip_rtm:");
}

/*
 * Clear the pending debug exceptions and RFLAGS.TF and re-enter
 * L2. No #DB is delivered and L2 continues to the next point of
 * interest.
 */
static void dismiss_db(void)
{
	vmcs_write(GUEST_PENDING_DEBUG, 0);
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED);
	enter_guest();
}

/*
 * Check a variety of VMCS fields relevant to an intercepted #DB exception.
 * Then throw away the #DB exception and resume L2.
 */
static void check_db_exit(bool xfail_qual, bool xfail_dr6, bool xfail_pdbg,
			  void *expected_rip, u64 expected_exit_qual,
			  u64 expected_dr6)
{
	u32 reason = vmcs_read(EXI_REASON);
	u32 intr_info = vmcs_read(EXI_INTR_INFO);
	u64 exit_qual = vmcs_read(EXI_QUALIFICATION);
	u64 guest_rip = vmcs_read(GUEST_RIP);
	u64 guest_pending_dbg = vmcs_read(GUEST_PENDING_DEBUG);
	u64 dr6 = read_dr6();
	const u32 expected_intr_info = INTR_INFO_VALID_MASK |
		INTR_TYPE_HARD_EXCEPTION | DB_VECTOR;

	report(reason == VMX_EXC_NMI && intr_info == expected_intr_info,
	       "Expected #DB VM-exit");
	report((u64)expected_rip == guest_rip, "Expected RIP %p (actual %lx)",
	       expected_rip, guest_rip);
	report_xfail(xfail_pdbg, 0 == guest_pending_dbg,
		     "Expected pending debug exceptions 0 (actual %lx)",
		     guest_pending_dbg);
	report_xfail(xfail_qual, expected_exit_qual == exit_qual,
		     "Expected exit qualification %lx (actual %lx)",
		     expected_exit_qual, exit_qual);
	report_xfail(xfail_dr6, expected_dr6 == dr6,
		     "Expected DR6 %lx (actual %lx)", expected_dr6, dr6);
	dismiss_db();
}

/*
 * Assuming the guest has just exited on a VMCALL instruction, skip
 * over the vmcall, and set the guest's RFLAGS.TF in the VMCS. If
 * pending debug exceptions are non-zero, set the VMCS up as if the
 * previous instruction was a MOVSS that generated the indicated
 * pending debug exceptions. Then enter L2.
 */
static void single_step_guest(const char *test_name, u64 starting_dr6,
			      u64 pending_debug_exceptions)
{
	printf("\n%s\n", test_name);
	skip_exit_vmcall();
	write_dr6(starting_dr6);
	vmcs_write(GUEST_RFLAGS, X86_EFLAGS_FIXED | X86_EFLAGS_TF);
	if (pending_debug_exceptions) {
		vmcs_write(GUEST_PENDING_DEBUG, pending_debug_exceptions);
		vmcs_write(GUEST_INTR_STATE, GUEST_INTR_STATE_MOVSS);
	}
	enter_guest();
}

/*
 * When L1 intercepts #DB, verify that a single-step trap clears
 * pending debug exceptions, populates the exit qualification field
 * properly, and that DR6 is not prematurely clobbered. In a
 * (simulated) MOVSS shadow, make sure that the pending debug
 * exception bits are properly accumulated into the exit qualification
 * field.
 */
static void vmx_db_test(void)
{
	/*
	 * We are going to set a few arbitrary bits in DR6 to verify that
	 * (a) DR6 is not modified by an intercepted #DB, and
	 * (b) stale bits in DR6 (DR6.BD, in particular) don't leak into
         *     the exit qualification field for a subsequent #DB exception.
	 */
	const u64 starting_dr6 = DR6_ACTIVE_LOW | DR6_BS | DR6_TRAP3 | DR6_TRAP1;
	extern char post_nop asm(".Lpost_nop");
	extern char post_movss_nop asm(".Lpost_movss_nop");
	extern char post_wbinvd asm(".Lpost_wbinvd");
	extern char post_movss_wbinvd asm(".Lpost_movss_wbinvd");
	extern char xbegin asm(".Lxbegin");
	extern char skip_rtm asm(".Lskip_rtm");

	/*
	 * L1 wants to intercept #DB exceptions encountered in L2.
	 */
	vmcs_write(EXC_BITMAP, BIT(DB_VECTOR));

	/*
	 * Start L2 and run it up to the first point of interest.
	 */
	test_set_guest(vmx_db_test_guest);
	enter_guest();

	/*
	 * Hardware-delivered #DB trap for single-step sets the
	 * standard that L0 has to follow for emulated instructions.
	 */
	single_step_guest("Hardware delivered single-step", starting_dr6, 0);
	check_db_exit(false, false, false, &post_nop, DR6_BS, starting_dr6);

	/*
	 * Hardware-delivered #DB trap for single-step in MOVSS shadow
	 * also sets the standard that L0 has to follow for emulated
	 * instructions. Here, we establish the VMCS pending debug
	 * exceptions to indicate that the simulated MOVSS triggered a
	 * data breakpoint as well as the single-step trap.
	 */
	single_step_guest("Hardware delivered single-step in MOVSS shadow",
			  starting_dr6, DR6_BS | PENDING_DBG_TRAP | DR6_TRAP0);
	check_db_exit(false, false, false, &post_movss_nop, DR6_BS | DR6_TRAP0,
		      starting_dr6);

	/*
	 * L0 synthesized #DB trap for single-step is buggy, because
	 * kvm (a) clobbers DR6 too early, and (b) tries its best to
	 * reconstitute the exit qualification from the prematurely
	 * modified DR6, but fails miserably.
	 */
	single_step_guest("Software synthesized single-step", starting_dr6, 0);
	check_db_exit(false, false, false, &post_wbinvd, DR6_BS, starting_dr6);

	/*
	 * L0 synthesized #DB trap for single-step in MOVSS shadow is
	 * even worse, because L0 also leaves the pending debug
	 * exceptions in the VMCS instead of accumulating them into
	 * the exit qualification field for the #DB exception.
	 */
	single_step_guest("Software synthesized single-step in MOVSS shadow",
			  starting_dr6, DR6_BS | PENDING_DBG_TRAP | DR6_TRAP0);
	check_db_exit(true, false, true, &post_movss_wbinvd, DR6_BS | DR6_TRAP0,
		      starting_dr6);

	/*
	 * Optional RTM test for hardware that supports RTM, to
	 * demonstrate that the current volume 3 of the SDM
	 * (325384-067US), table 27-1 is incorrect. Bit 16 of the exit
	 * qualification for debug exceptions is not reserved. It is
	 * set to 1 if a debug exception (#DB) or a breakpoint
	 * exception (#BP) occurs inside an RTM region while advanced
	 * debugging of RTM transactional regions is enabled.
	 */
	if (this_cpu_has(X86_FEATURE_RTM)) {
		vmcs_write(ENT_CONTROLS,
			   vmcs_read(ENT_CONTROLS) | ENT_LOAD_DBGCTLS);
		/*
		 * Set DR7.RTM[bit 11] and IA32_DEBUGCTL.RTM[bit 15]
		 * in the guest to enable advanced debugging of RTM
		 * transactional regions.
		 */
		vmcs_write(GUEST_DR7, BIT(11));
		vmcs_write(GUEST_DEBUGCTL, BIT(15));
		single_step_guest("Hardware delivered single-step in "
				  "transactional region", starting_dr6, 0);
		check_db_exit(false, false, false, &xbegin, BIT(16),
			      starting_dr6);
	} else {
		vmcs_write(GUEST_RIP, (u64)&skip_rtm);
		enter_guest();
	}
}

static void enable_vid(void)
{
	void *virtual_apic_page;

	assert(cpu_has_apicv());

	disable_intercept_for_x2apic_msrs();

	virtual_apic_page = alloc_page();
	vmcs_write(APIC_VIRT_ADDR, (u64)virtual_apic_page);

	vmcs_set_bits(PIN_CONTROLS, PIN_EXTINT);

	vmcs_write(EOI_EXIT_BITMAP0, 0x0);
	vmcs_write(EOI_EXIT_BITMAP1, 0x0);
	vmcs_write(EOI_EXIT_BITMAP2, 0x0);
	vmcs_write(EOI_EXIT_BITMAP3, 0x0);

	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_SECONDARY | CPU_TPR_SHADOW);
	vmcs_set_bits(CPU_EXEC_CTRL1, CPU_VINTD | CPU_VIRT_X2APIC);
}

static void trigger_ioapic_scan_thread(void *data)
{
	/* Wait until other CPU entered L2 */
	while (vmx_get_test_stage() != 1)
		;

	/* Trigger ioapic scan */
	ioapic_set_redir(0xf, 0x79, TRIGGER_LEVEL);
	vmx_set_test_stage(2);
}

static void irq_79_handler_guest(isr_regs_t *regs)
{
	eoi();

	/* L1 expects vmexit on VMX_VMCALL and not VMX_EOI_INDUCED */
	vmcall();
}

/*
 * Constant for num of busy-loop iterations after which
 * a timer interrupt should have happened in host
 */
#define TIMER_INTERRUPT_DELAY 100000000

static void vmx_eoi_bitmap_ioapic_scan_test_guest(void)
{
	handle_irq(0x79, irq_79_handler_guest);
	irq_enable();

	/* Signal to L1 CPU to trigger ioapic scan */
	vmx_set_test_stage(1);
	/* Wait until L1 CPU to trigger ioapic scan */
	while (vmx_get_test_stage() != 2)
		;

	/*
	 * Wait for L0 timer interrupt to be raised while we run in L2
	 * such that L0 will process the IOAPIC scan request before
	 * resuming L2
	 */
	delay(TIMER_INTERRUPT_DELAY);

	asm volatile ("int $0x79");
}

static void vmx_eoi_bitmap_ioapic_scan_test(void)
{
	if (!cpu_has_apicv() || (cpu_count() < 2)) {
		report_skip("%s : Not all required APICv bits supported or CPU count < 2", __func__);
		return;
	}

	enable_vid();

	on_cpu_async(1, trigger_ioapic_scan_thread, NULL);
	test_set_guest(vmx_eoi_bitmap_ioapic_scan_test_guest);

	/*
	 * Launch L2.
	 * We expect the exit reason to be VMX_VMCALL (and not EOI INDUCED).
	 * In case the reason isn't VMX_VMCALL, the asserion inside
	 * skip_exit_vmcall() will fail.
	 */
	enter_guest();
	skip_exit_vmcall();

	/* Let L2 finish */
	enter_guest();
	report_pass(__func__);
}

#define HLT_WITH_RVI_VECTOR		(0xf1)

bool vmx_hlt_with_rvi_guest_isr_fired;
static void vmx_hlt_with_rvi_guest_isr(isr_regs_t *regs)
{
	vmx_hlt_with_rvi_guest_isr_fired = true;
	eoi();
}

static void vmx_hlt_with_rvi_guest(void)
{
	handle_irq(HLT_WITH_RVI_VECTOR, vmx_hlt_with_rvi_guest_isr);

	irq_enable();
	asm volatile ("nop");

	vmcall();
}

static void vmx_hlt_with_rvi_test(void)
{
	if (!cpu_has_apicv()) {
		report_skip("%s : Not all required APICv bits supported", __func__);
		return;
	}

	enable_vid();

	vmx_hlt_with_rvi_guest_isr_fired = false;
	test_set_guest(vmx_hlt_with_rvi_guest);

	enter_guest();
	skip_exit_vmcall();

	vmcs_write(GUEST_ACTV_STATE, ACTV_HLT);
	vmcs_write(GUEST_INT_STATUS, HLT_WITH_RVI_VECTOR);
	enter_guest();

	report(vmx_hlt_with_rvi_guest_isr_fired, "Interrupt raised in guest");
}

static void set_irq_line_thread(void *data)
{
	/* Wait until other CPU entered L2 */
	while (vmx_get_test_stage() != 1)
		;

	/* Set irq-line 0xf to raise vector 0x78 for vCPU 0 */
	ioapic_set_redir(0xf, 0x78, TRIGGER_LEVEL);
	vmx_set_test_stage(2);
}

static bool irq_78_handler_vmcall_before_eoi;
static void irq_78_handler_guest(isr_regs_t *regs)
{
	set_irq_line(0xf, 0);
	if (irq_78_handler_vmcall_before_eoi)
		vmcall();
	eoi();
	vmcall();
}

static void vmx_apic_passthrough_guest(void)
{
	handle_irq(0x78, irq_78_handler_guest);
	irq_enable();

	/* If requested, wait for other CPU to trigger ioapic scan */
	if (vmx_get_test_stage() < 1) {
		vmx_set_test_stage(1);
		while (vmx_get_test_stage() != 2)
			;
	}

	set_irq_line(0xf, 1);
}

static void vmx_apic_passthrough(bool set_irq_line_from_thread)
{
	if (set_irq_line_from_thread && (cpu_count() < 2)) {
		report_skip("%s : CPU count < 2", __func__);
		return;
	}

	/* Test device is required for generating IRQs */
	if (!test_device_enabled()) {
		report_skip("%s : No test device enabled", __func__);
		return;
	}
	u64 cpu_ctrl_0 = CPU_SECONDARY;
	u64 cpu_ctrl_1 = 0;

	disable_intercept_for_x2apic_msrs();

	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);

	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | cpu_ctrl_0);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | cpu_ctrl_1);

	if (set_irq_line_from_thread) {
		irq_78_handler_vmcall_before_eoi = false;
		on_cpu_async(1, set_irq_line_thread, NULL);
	} else {
		irq_78_handler_vmcall_before_eoi = true;
		ioapic_set_redir(0xf, 0x78, TRIGGER_LEVEL);
		vmx_set_test_stage(2);
	}
	test_set_guest(vmx_apic_passthrough_guest);

	if (irq_78_handler_vmcall_before_eoi) {
		/* Before EOI remote_irr should still be set */
		enter_guest();
		skip_exit_vmcall();
		TEST_ASSERT_EQ_MSG(1, (int)ioapic_read_redir(0xf).remote_irr,
			"IOAPIC pass-through: remote_irr=1 before EOI");
	}

	/* After EOI remote_irr should be cleared */
	enter_guest();
	skip_exit_vmcall();
	TEST_ASSERT_EQ_MSG(0, (int)ioapic_read_redir(0xf).remote_irr,
		"IOAPIC pass-through: remote_irr=0 after EOI");

	/* Let L2 finish */
	enter_guest();
	report_pass(__func__);
}

static void vmx_apic_passthrough_test(void)
{
	vmx_apic_passthrough(false);
}

static void vmx_apic_passthrough_thread_test(void)
{
	vmx_apic_passthrough(true);
}

static void vmx_apic_passthrough_tpr_threshold_guest(void)
{
	cli();
	apic_set_tpr(0);
}

static bool vmx_apic_passthrough_tpr_threshold_ipi_isr_fired;
static void vmx_apic_passthrough_tpr_threshold_ipi_isr(isr_regs_t *regs)
{
	vmx_apic_passthrough_tpr_threshold_ipi_isr_fired = true;
	eoi();
}

static void vmx_apic_passthrough_tpr_threshold_test(void)
{
	int ipi_vector = 0xe1;

	disable_intercept_for_x2apic_msrs();
	vmcs_clear_bits(PIN_CONTROLS, PIN_EXTINT);

	/* Raise L0 TPR-threshold by queueing vector in LAPIC IRR */
	cli();
	apic_set_tpr((ipi_vector >> 4) + 1);
	apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL |
			APIC_DM_FIXED | ipi_vector,
			0);

	test_set_guest(vmx_apic_passthrough_tpr_threshold_guest);
	enter_guest();

	report(apic_get_tpr() == 0, "TPR was zero by guest");

	/* Clean pending self-IPI */
	vmx_apic_passthrough_tpr_threshold_ipi_isr_fired = false;
	handle_irq(ipi_vector, vmx_apic_passthrough_tpr_threshold_ipi_isr);
	sti();
	asm volatile ("nop");
	report(vmx_apic_passthrough_tpr_threshold_ipi_isr_fired, "self-IPI fired");

	report_pass(__func__);
}

static u64 init_signal_test_exit_reason;
static bool init_signal_test_thread_continued;

static void init_signal_test_thread(void *data)
{
	struct vmcs *test_vmcs = data;

	/* Enter VMX operation (i.e. exec VMXON) */
	u64 *ap_vmxon_region = alloc_page();
	enable_vmx();
	init_vmx(ap_vmxon_region);
	TEST_ASSERT(!__vmxon_safe(ap_vmxon_region));

	/* Signal CPU have entered VMX operation */
	vmx_set_test_stage(1);

	/* Wait for BSP CPU to send INIT signal */
	while (vmx_get_test_stage() != 2)
		;

	/*
	 * Signal that we continue as usual as INIT signal
	 * should be blocked while CPU is in VMX operation
	 */
	vmx_set_test_stage(3);

	/* Wait for signal to enter VMX non-root mode */
	while (vmx_get_test_stage() != 4)
		;

	/* Enter VMX non-root mode */
	test_set_guest(v2_null_test_guest);
	make_vmcs_current(test_vmcs);
	enter_guest();
	/* Save exit reason for BSP CPU to compare to expected result */
	init_signal_test_exit_reason = vmcs_read(EXI_REASON);
	/* VMCLEAR test-vmcs so it could be loaded by BSP CPU */
	vmcs_clear(test_vmcs);
	launched = false;
	/* Signal that CPU exited to VMX root mode */
	vmx_set_test_stage(5);

	/* Wait for BSP CPU to signal to exit VMX operation */
	while (vmx_get_test_stage() != 6)
		;

	/* Exit VMX operation (i.e. exec VMXOFF) */
	vmx_off();

	/*
	 * Signal to BSP CPU that we continue as usual as INIT signal
	 * should have been consumed by VMX_INIT exit from guest
	 */
	vmx_set_test_stage(7);

	/* Wait for BSP CPU to signal to enter VMX operation */
	while (vmx_get_test_stage() != 8)
		;
	/* Enter VMX operation (i.e. exec VMXON) */
	TEST_ASSERT(!__vmxon_safe(ap_vmxon_region));
	/* Signal to BSP we are in VMX operation */
	vmx_set_test_stage(9);

	/* Wait for BSP CPU to send INIT signal */
	while (vmx_get_test_stage() != 10)
		;

	/* Exit VMX operation (i.e. exec VMXOFF) */
	vmx_off();

	/*
	 * Exiting VMX operation should result in latched
	 * INIT signal being processed. Therefore, we should
	 * never reach the below code. Thus, signal to BSP
	 * CPU if we have reached here so it is able to
	 * report an issue if it happens.
	 */
	init_signal_test_thread_continued = true;
}

#define INIT_SIGNAL_TEST_DELAY	100000000ULL

static void vmx_init_signal_test(void)
{
	struct vmcs *test_vmcs;

	if (cpu_count() < 2) {
		report_skip("%s : CPU count < 2", __func__);
		return;
	}

	/* VMCLEAR test-vmcs so it could be loaded by other CPU */
	vmcs_save(&test_vmcs);
	vmcs_clear(test_vmcs);

	vmx_set_test_stage(0);
	on_cpu_async(1, init_signal_test_thread, test_vmcs);

	/* Wait for other CPU to enter VMX operation */
	while (vmx_get_test_stage() != 1)
		;

	/* Send INIT signal to other CPU */
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT,
				   id_map[1]);
	/* Signal other CPU we have sent INIT signal */
	vmx_set_test_stage(2);

	/*
	 * Wait reasonable amount of time for INIT signal to
	 * be received on other CPU and verify that other CPU
	 * have proceed as usual to next test stage as INIT
	 * signal should be blocked while other CPU in
	 * VMX operation
	 */
	delay(INIT_SIGNAL_TEST_DELAY);
	report(vmx_get_test_stage() == 3,
	       "INIT signal blocked when CPU in VMX operation");
	/* No point to continue if we failed at this point */
	if (vmx_get_test_stage() != 3)
		return;

	/* Signal other CPU to enter VMX non-root mode */
	init_signal_test_exit_reason = -1ull;
	vmx_set_test_stage(4);
	/*
	 * Wait reasonable amont of time for other CPU
	 * to exit to VMX root mode
	 */
	delay(INIT_SIGNAL_TEST_DELAY);
	if (vmx_get_test_stage() != 5) {
		report_fail("Pending INIT signal didn't result in VMX exit");
		return;
	}
	report(init_signal_test_exit_reason == VMX_INIT,
			"INIT signal during VMX non-root mode result in exit-reason %s (%lu)",
			exit_reason_description(init_signal_test_exit_reason),
			init_signal_test_exit_reason);

	/* Run guest to completion */
	make_vmcs_current(test_vmcs);
	enter_guest();

	/* Signal other CPU to exit VMX operation */
	init_signal_test_thread_continued = false;
	vmx_set_test_stage(6);

	/* Wait reasonable amount of time for other CPU to exit VMX operation */
	delay(INIT_SIGNAL_TEST_DELAY);
	report(vmx_get_test_stage() == 7,
	       "INIT signal consumed on VMX_INIT exit");
	/* No point to continue if we failed at this point */
	if (vmx_get_test_stage() != 7)
		return;

	/* Signal other CPU to enter VMX operation */
	vmx_set_test_stage(8);
	/* Wait for other CPU to enter VMX operation */
	while (vmx_get_test_stage() != 9)
		;

	/* Send INIT signal to other CPU */
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT,
				   id_map[1]);
	/* Signal other CPU we have sent INIT signal */
	vmx_set_test_stage(10);

	/*
	 * Wait reasonable amount of time for other CPU
	 * to exit VMX operation and process INIT signal
	 */
	delay(INIT_SIGNAL_TEST_DELAY);
	report(!init_signal_test_thread_continued,
	       "INIT signal processed after exit VMX operation");

	/*
	 * TODO: Send SIPI to other CPU to sipi_entry (See x86/cstart64.S)
	 * to re-init it to kvm-unit-tests standard environment.
	 * Somehow (?) verify that SIPI was indeed received.
	 */
}

#define SIPI_SIGNAL_TEST_DELAY	100000000ULL

static void vmx_sipi_test_guest(void)
{
	if (apic_id() == 0) {
		/* wait AP enter guest with activity=WAIT_SIPI */
		while (vmx_get_test_stage() != 1)
			;
		delay(SIPI_SIGNAL_TEST_DELAY);

		/* First SIPI signal */
		apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_STARTUP | APIC_INT_ASSERT, id_map[1]);
		report_pass("BSP(L2): Send first SIPI to cpu[%d]", id_map[1]);

		/* wait AP enter guest */
		while (vmx_get_test_stage() != 2)
			;
		delay(SIPI_SIGNAL_TEST_DELAY);

		/* Second SIPI signal should be ignored since AP is not in WAIT_SIPI state */
		apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_STARTUP | APIC_INT_ASSERT, id_map[1]);
		report_pass("BSP(L2): Send second SIPI to cpu[%d]", id_map[1]);

		/* Delay a while to check whether second SIPI would cause VMExit */
		delay(SIPI_SIGNAL_TEST_DELAY);

		/* Test is done, notify AP to exit test */
		vmx_set_test_stage(3);

		/* wait AP exit non-root mode */
		while (vmx_get_test_stage() != 5)
			;
	} else {
		/* wait BSP notify test is done */
		while (vmx_get_test_stage() != 3)
			;

		/* AP exit guest */
		vmx_set_test_stage(4);
	}
}

static void sipi_test_ap_thread(void *data)
{
	struct vmcs *ap_vmcs;
	u64 *ap_vmxon_region;
	void *ap_stack, *ap_syscall_stack;
	u64 cpu_ctrl_0 = CPU_SECONDARY;
	u64 cpu_ctrl_1 = 0;

	/* Enter VMX operation (i.e. exec VMXON) */
	ap_vmxon_region = alloc_page();
	enable_vmx();
	init_vmx(ap_vmxon_region);
	TEST_ASSERT(!__vmxon_safe(ap_vmxon_region));
	init_vmcs(&ap_vmcs);
	make_vmcs_current(ap_vmcs);

	/* Set stack for AP */
	ap_stack = alloc_page();
	ap_syscall_stack = alloc_page();
	vmcs_write(GUEST_RSP, (u64)(ap_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_SYSENTER_ESP, (u64)(ap_syscall_stack + PAGE_SIZE - 1));

	/* passthrough lapic to L2 */
	disable_intercept_for_x2apic_msrs();
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);
	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | cpu_ctrl_0);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | cpu_ctrl_1);

	/* Set guest activity state to wait-for-SIPI state */
	vmcs_write(GUEST_ACTV_STATE, ACTV_WAIT_SIPI);

	vmx_set_test_stage(1);

	/* AP enter guest */
	enter_guest();

	if (vmcs_read(EXI_REASON) == VMX_SIPI) {
		report_pass("AP: Handle SIPI VMExit");
		vmcs_write(GUEST_ACTV_STATE, ACTV_ACTIVE);
		vmx_set_test_stage(2);
	} else {
		report_fail("AP: Unexpected VMExit, reason=%ld", vmcs_read(EXI_REASON));
		vmx_off();
		return;
	}

	/* AP enter guest */
	enter_guest();

	report(vmcs_read(EXI_REASON) != VMX_SIPI,
		"AP: should no SIPI VMExit since activity is not in WAIT_SIPI state");

	/* notify BSP that AP is already exit from non-root mode */
	vmx_set_test_stage(5);

	/* Leave VMX operation */
	vmx_off();
}

static void vmx_sipi_signal_test(void)
{
	if (!(rdmsr(MSR_IA32_VMX_MISC) & MSR_IA32_VMX_MISC_ACTIVITY_WAIT_SIPI)) {
		report_skip("%s : \"ACTIVITY_WAIT_SIPI state\" not supported", __func__);
		return;
	}

	if (cpu_count() < 2) {
		report_skip("%s : CPU count < 2", __func__);
		return;
	}

	u64 cpu_ctrl_0 = CPU_SECONDARY;
	u64 cpu_ctrl_1 = 0;

	/* passthrough lapic to L2 */
	disable_intercept_for_x2apic_msrs();
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) & ~PIN_EXTINT);
	vmcs_write(CPU_EXEC_CTRL0, vmcs_read(CPU_EXEC_CTRL0) | cpu_ctrl_0);
	vmcs_write(CPU_EXEC_CTRL1, vmcs_read(CPU_EXEC_CTRL1) | cpu_ctrl_1);

	test_set_guest(vmx_sipi_test_guest);

	/* update CR3 on AP */
	on_cpu(1, update_cr3, (void *)read_cr3());

	/* start AP */
	on_cpu_async(1, sipi_test_ap_thread, NULL);

	vmx_set_test_stage(0);

	/* BSP enter guest */
	enter_guest();
}


enum vmcs_access {
	ACCESS_VMREAD,
	ACCESS_VMWRITE,
	ACCESS_NONE,
};

struct vmcs_shadow_test_common {
	enum vmcs_access op;
	enum Reason reason;
	u64 field;
	u64 value;
	u64 flags;
	u64 time;
} l1_l2_common;

static inline u64 vmread_flags(u64 field, u64 *val)
{
	u64 flags;

	asm volatile ("vmread %2, %1; pushf; pop %0"
		      : "=r" (flags), "=rm" (*val) : "r" (field) : "cc");
	return flags & X86_EFLAGS_ALU;
}

static inline u64 vmwrite_flags(u64 field, u64 val)
{
	u64 flags;

	asm volatile ("vmwrite %1, %2; pushf; pop %0"
		      : "=r"(flags) : "rm" (val), "r" (field) : "cc");
	return flags & X86_EFLAGS_ALU;
}

static void vmx_vmcs_shadow_test_guest(void)
{
	struct vmcs_shadow_test_common *c = &l1_l2_common;
	u64 start;

	while (c->op != ACCESS_NONE) {
		start = rdtsc();
		switch (c->op) {
		default:
			c->flags = -1ull;
			break;
		case ACCESS_VMREAD:
			c->flags = vmread_flags(c->field, &c->value);
			break;
		case ACCESS_VMWRITE:
			c->flags = vmwrite_flags(c->field, 0);
			break;
		}
		c->time = rdtsc() - start;
		vmcall();
	}
}

static u64 vmread_from_shadow(u64 field)
{
	struct vmcs *primary;
	struct vmcs *shadow;
	u64 value;

	TEST_ASSERT(!vmcs_save(&primary));
	shadow = (struct vmcs *)vmcs_read(VMCS_LINK_PTR);
	TEST_ASSERT(!make_vmcs_current(shadow));
	value = vmcs_read(field);
	TEST_ASSERT(!make_vmcs_current(primary));
	return value;
}

static u64 vmwrite_to_shadow(u64 field, u64 value)
{
	struct vmcs *primary;
	struct vmcs *shadow;

	TEST_ASSERT(!vmcs_save(&primary));
	shadow = (struct vmcs *)vmcs_read(VMCS_LINK_PTR);
	TEST_ASSERT(!make_vmcs_current(shadow));
	vmcs_write(field, value);
	value = vmcs_read(field);
	TEST_ASSERT(!make_vmcs_current(primary));
	return value;
}

static void vmcs_shadow_test_access(u8 *bitmap[2], enum vmcs_access access)
{
	struct vmcs_shadow_test_common *c = &l1_l2_common;

	c->op = access;
	vmcs_write(VMX_INST_ERROR, 0);
	enter_guest();
	c->reason = vmcs_read(EXI_REASON) & 0xffff;
	if (c->reason != VMX_VMCALL) {
		skip_exit_insn();
		enter_guest();
	}
	skip_exit_vmcall();
}

static void vmcs_shadow_test_field(u8 *bitmap[2], u64 field)
{
	struct vmcs_shadow_test_common *c = &l1_l2_common;
	struct vmcs *shadow;
	u64 value;
	uintptr_t flags[2];
	bool good_shadow;
	u32 vmx_inst_error;

	report_prefix_pushf("field %lx", field);
	c->field = field;

	shadow = (struct vmcs *)vmcs_read(VMCS_LINK_PTR);
	if (shadow != (struct vmcs *)-1ull) {
		flags[ACCESS_VMREAD] = vmread_flags(field, &value);
		flags[ACCESS_VMWRITE] = vmwrite_flags(field, value);
		good_shadow = !flags[ACCESS_VMREAD] && !flags[ACCESS_VMWRITE];
	} else {
		/*
		 * When VMCS link pointer is -1ull, VMWRITE/VMREAD on
		 * shadowed-fields should fail with setting RFLAGS.CF.
		 */
		flags[ACCESS_VMREAD] = X86_EFLAGS_CF;
		flags[ACCESS_VMWRITE] = X86_EFLAGS_CF;
		good_shadow = false;
	}

	/* Intercept both VMREAD and VMWRITE. */
	report_prefix_push("no VMREAD/VMWRITE permission");
	/* VMWRITE/VMREAD done on reserved-bit should always intercept */
	if (!(field >> VMCS_FIELD_RESERVED_SHIFT)) {
		set_bit(field, bitmap[ACCESS_VMREAD]);
		set_bit(field, bitmap[ACCESS_VMWRITE]);
	}
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	report(c->reason == VMX_VMWRITE, "not shadowed for VMWRITE");
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	report(c->reason == VMX_VMREAD, "not shadowed for VMREAD");
	report_prefix_pop();

	if (field >> VMCS_FIELD_RESERVED_SHIFT)
		goto out;

	/* Permit shadowed VMREAD. */
	report_prefix_push("VMREAD permission only");
	clear_bit(field, bitmap[ACCESS_VMREAD]);
	set_bit(field, bitmap[ACCESS_VMWRITE]);
	if (good_shadow)
		value = vmwrite_to_shadow(field, MAGIC_VAL_1 + field);
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	report(c->reason == VMX_VMWRITE, "not shadowed for VMWRITE");
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report(c->reason == VMX_VMCALL, "shadowed for VMREAD (in %ld cycles)",
	       c->time);
	report(c->flags == flags[ACCESS_VMREAD],
	       "ALU flags after VMREAD (%lx) are as expected (%lx)",
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow)
		report(c->value == value,
		       "value read from shadow (%lx) is as expected (%lx)",
		       c->value, value);
	else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMREAD])
		report(vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       "VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	report_prefix_pop();

	/* Permit shadowed VMWRITE. */
	report_prefix_push("VMWRITE permission only");
	set_bit(field, bitmap[ACCESS_VMREAD]);
	clear_bit(field, bitmap[ACCESS_VMWRITE]);
	if (good_shadow)
		vmwrite_to_shadow(field, MAGIC_VAL_1 + field);
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report(c->reason == VMX_VMCALL,
		"shadowed for VMWRITE (in %ld cycles)",
		c->time);
	report(c->flags == flags[ACCESS_VMREAD],
	       "ALU flags after VMWRITE (%lx) are as expected (%lx)",
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow) {
		value = vmread_from_shadow(field);
		report(value == 0,
		       "shadow VMCS value (%lx) is as expected (%lx)", value,
		       0ul);
	} else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMWRITE]) {
		report(vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       "VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	}
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	report(c->reason == VMX_VMREAD, "not shadowed for VMREAD");
	report_prefix_pop();

	/* Permit shadowed VMREAD and VMWRITE. */
	report_prefix_push("VMREAD and VMWRITE permission");
	clear_bit(field, bitmap[ACCESS_VMREAD]);
	clear_bit(field, bitmap[ACCESS_VMWRITE]);
	if (good_shadow)
		vmwrite_to_shadow(field, MAGIC_VAL_1 + field);
	vmcs_shadow_test_access(bitmap, ACCESS_VMWRITE);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report(c->reason == VMX_VMCALL,
		"shadowed for VMWRITE (in %ld cycles)",
		c->time);
	report(c->flags == flags[ACCESS_VMREAD],
	       "ALU flags after VMWRITE (%lx) are as expected (%lx)",
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow) {
		value = vmread_from_shadow(field);
		report(value == 0,
		       "shadow VMCS value (%lx) is as expected (%lx)", value,
		       0ul);
	} else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMWRITE]) {
		report(vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       "VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	}
	vmcs_shadow_test_access(bitmap, ACCESS_VMREAD);
	vmx_inst_error = vmcs_read(VMX_INST_ERROR);
	report(c->reason == VMX_VMCALL, "shadowed for VMREAD (in %ld cycles)",
	       c->time);
	report(c->flags == flags[ACCESS_VMREAD],
	       "ALU flags after VMREAD (%lx) are as expected (%lx)",
	       c->flags, flags[ACCESS_VMREAD]);
	if (good_shadow)
		report(c->value == 0,
		       "value read from shadow (%lx) is as expected (%lx)",
		       c->value, 0ul);
	else if (shadow != (struct vmcs *)-1ull && flags[ACCESS_VMREAD])
		report(vmx_inst_error == VMXERR_UNSUPPORTED_VMCS_COMPONENT,
		       "VMX_INST_ERROR (%d) is as expected (%d)",
		       vmx_inst_error, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
	report_prefix_pop();

out:
	report_prefix_pop();
}

static void vmx_vmcs_shadow_test_body(u8 *bitmap[2])
{
	unsigned base;
	unsigned index;
	unsigned bit;
	unsigned highest_index = rdmsr(MSR_IA32_VMX_VMCS_ENUM);

	/* Run test on all possible valid VMCS fields */
	for (base = 0;
	     base < (1 << VMCS_FIELD_RESERVED_SHIFT);
	     base += (1 << VMCS_FIELD_TYPE_SHIFT))
		for (index = 0; index <= highest_index; index++)
			vmcs_shadow_test_field(bitmap, base + index);

	/*
	 * Run tests on some invalid VMCS fields
	 * (Have reserved bit set).
	 */
	for (bit = VMCS_FIELD_RESERVED_SHIFT; bit < VMCS_FIELD_BIT_SIZE; bit++)
		vmcs_shadow_test_field(bitmap, (1ull << bit));
}

static void vmx_vmcs_shadow_test(void)
{
	u8 *bitmap[2];
	struct vmcs *shadow;

	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY)) {
		report_skip("%s : \"Activate secondary controls\" not supported", __func__);
		return;
	}

	if (!(ctrl_cpu_rev[1].clr & CPU_SHADOW_VMCS)) {
		report_skip("%s : \"VMCS shadowing\" not supported", __func__);
		return;
	}

	if (!(rdmsr(MSR_IA32_VMX_MISC) &
	      MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS)) {
		report_skip("%s : VMWRITE can't modify VM-exit information fields.", __func__);
		return;
	}

	test_set_guest(vmx_vmcs_shadow_test_guest);

	bitmap[ACCESS_VMREAD] = alloc_page();
	bitmap[ACCESS_VMWRITE] = alloc_page();

	vmcs_write(VMREAD_BITMAP, virt_to_phys(bitmap[ACCESS_VMREAD]));
	vmcs_write(VMWRITE_BITMAP, virt_to_phys(bitmap[ACCESS_VMWRITE]));

	shadow = alloc_page();
	shadow->hdr.revision_id = basic.revision;
	shadow->hdr.shadow_vmcs = 1;
	TEST_ASSERT(!vmcs_clear(shadow));

	vmcs_clear_bits(CPU_EXEC_CTRL0, CPU_RDTSC);
	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_SECONDARY);
	vmcs_set_bits(CPU_EXEC_CTRL1, CPU_SHADOW_VMCS);

	vmcs_write(VMCS_LINK_PTR, virt_to_phys(shadow));
	report_prefix_push("valid link pointer");
	vmx_vmcs_shadow_test_body(bitmap);
	report_prefix_pop();

	vmcs_write(VMCS_LINK_PTR, -1ull);
	report_prefix_push("invalid link pointer");
	vmx_vmcs_shadow_test_body(bitmap);
	report_prefix_pop();

	l1_l2_common.op = ACCESS_NONE;
	enter_guest();
}

/*
 * This test monitors the difference between a guest RDTSC instruction
 * and the IA32_TIME_STAMP_COUNTER MSR value stored in the VMCS12
 * VM-exit MSR-store list when taking a VM-exit on the instruction
 * following RDTSC.
 */
#define RDTSC_DIFF_ITERS 100000
#define RDTSC_DIFF_FAILS 100
#define HOST_CAPTURED_GUEST_TSC_DIFF_THRESHOLD 750

/*
 * Set 'use TSC offsetting' and set the guest offset to the
 * inverse of the host's current TSC value, so that the guest starts running
 * with an effective TSC value of 0.
 */
static void reset_guest_tsc_to_zero(void)
{
	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_USE_TSC_OFFSET);
	vmcs_write(TSC_OFFSET, -rdtsc());
}

static void rdtsc_vmexit_diff_test_guest(void)
{
	int i;

	for (i = 0; i < RDTSC_DIFF_ITERS; i++)
		/* Ensure rdtsc is the last instruction before the vmcall. */
		asm volatile("rdtsc; vmcall" : : : "eax", "edx");
}

/*
 * This function only considers the "use TSC offsetting" VM-execution
 * control.  It does not handle "use TSC scaling" (because the latter
 * isn't available to the host today.)
 */
static unsigned long long host_time_to_guest_time(unsigned long long t)
{
	TEST_ASSERT(!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
		    !(vmcs_read(CPU_EXEC_CTRL1) & CPU_USE_TSC_SCALING));

	if (vmcs_read(CPU_EXEC_CTRL0) & CPU_USE_TSC_OFFSET)
		t += vmcs_read(TSC_OFFSET);

	return t;
}

static unsigned long long rdtsc_vmexit_diff_test_iteration(void)
{
	unsigned long long guest_tsc, host_to_guest_tsc;

	enter_guest();
	skip_exit_vmcall();
	guest_tsc = (u32) regs.rax + (regs.rdx << 32);
	host_to_guest_tsc = host_time_to_guest_time(exit_msr_store[0].value);

	return host_to_guest_tsc - guest_tsc;
}

static void rdtsc_vmexit_diff_test(void)
{
	unsigned long long delta;
	int fail = 0;
	int i;

	if (!(ctrl_cpu_rev[0].clr & CPU_USE_TSC_OFFSET))
		test_skip("CPU doesn't support the 'use TSC offsetting' processor-based VM-execution control.\n");

	test_set_guest(rdtsc_vmexit_diff_test_guest);

	reset_guest_tsc_to_zero();

	/*
	 * Set up the VMCS12 VM-exit MSR-store list to store just one
	 * MSR: IA32_TIME_STAMP_COUNTER. Note that the value stored is
	 * in the host time domain (i.e., it is not adjusted according
	 * to the TSC multiplier and TSC offset fields in the VMCS12,
	 * as a guest RDTSC would be.)
	 */
	exit_msr_store = alloc_page();
	exit_msr_store[0].index = MSR_IA32_TSC;
	vmcs_write(EXI_MSR_ST_CNT, 1);
	vmcs_write(EXIT_MSR_ST_ADDR, virt_to_phys(exit_msr_store));

	for (i = 0; i < RDTSC_DIFF_ITERS && fail < RDTSC_DIFF_FAILS; i++) {
		delta = rdtsc_vmexit_diff_test_iteration();
		if (delta >= HOST_CAPTURED_GUEST_TSC_DIFF_THRESHOLD)
			fail++;
	}

	enter_guest();

	report(fail < RDTSC_DIFF_FAILS,
	       "RDTSC to VM-exit delta too high in %d of %d iterations, last = %llu",
	       fail, i, delta);
}

static int invalid_msr_init(struct vmcs *vmcs)
{
	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		printf("\tPreemption timer is not supported\n");
		return VMX_TEST_EXIT;
	}
	vmcs_write(PIN_CONTROLS, vmcs_read(PIN_CONTROLS) | PIN_PREEMPT);
	preempt_val = 10000000;
	vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
	preempt_scale = rdmsr(MSR_IA32_VMX_MISC) & 0x1F;

	if (!(ctrl_exit_rev.clr & EXI_SAVE_PREEMPT))
		printf("\tSave preemption value is not supported\n");

	vmcs_write(ENT_MSR_LD_CNT, 1);
	vmcs_write(ENTER_MSR_LD_ADDR, (u64)0x13370000);

	return VMX_TEST_START;
}


static void invalid_msr_main(void)
{
	report_fail("Invalid MSR load");
}

static int invalid_msr_exit_handler(union exit_reason exit_reason)
{
	report_fail("Invalid MSR load");
	print_vmexit_info(exit_reason);
	return VMX_TEST_EXIT;
}

static int invalid_msr_entry_failure(struct vmentry_result *result)
{
	report(result->exit_reason.failed_vmentry &&
	       result->exit_reason.basic == VMX_FAIL_MSR, "Invalid MSR load");
	return VMX_TEST_VMEXIT;
}

/*
 * The max number of MSRs in an atomic switch MSR list is:
 * (111B + 1) * 512 = 4096
 *
 * Each list entry consumes:
 * 4-byte MSR index + 4 bytes reserved + 8-byte data = 16 bytes
 *
 * Allocate 128 kB to cover max_msr_list_size (i.e., 64 kB) and then some.
 */
static const u32 msr_list_page_order = 5;

static void atomic_switch_msr_limit_test_guest(void)
{
	vmcall();
}

static void populate_msr_list(struct vmx_msr_entry *msr_list,
			      size_t byte_capacity, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		msr_list[i].index = MSR_IA32_TSC;
		msr_list[i].reserved = 0;
		msr_list[i].value = 0x1234567890abcdef;
	}

	memset(msr_list + count, 0xff,
	       byte_capacity - count * sizeof(*msr_list));
}

static int max_msr_list_size(void)
{
	u32 vmx_misc = rdmsr(MSR_IA32_VMX_MISC);
	u32 factor = ((vmx_misc & GENMASK(27, 25)) >> 25) + 1;

	return factor * 512;
}

static void atomic_switch_msrs_test(int count)
{
	struct vmx_msr_entry *vm_enter_load;
        struct vmx_msr_entry *vm_exit_load;
        struct vmx_msr_entry *vm_exit_store;
	int max_allowed = max_msr_list_size();
	int byte_capacity = 1ul << (msr_list_page_order + PAGE_SHIFT);
	/* Exceeding the max MSR list size at exit triggers KVM to abort. */
	int exit_count = count > max_allowed ? max_allowed : count;
	int cleanup_count = count > max_allowed ? 2 : 1;
	int i;

	/*
	 * Check for the IA32_TSC MSR,
	 * available with the "TSC flag" and used to populate the MSR lists.
	 */
	if (!(cpuid(1).d & (1 << 4))) {
		report_skip("%s : \"Time Stamp Counter\" not supported", __func__);
		return;
	}

	/* Set L2 guest. */
	test_set_guest(atomic_switch_msr_limit_test_guest);

	/* Setup atomic MSR switch lists. */
	vm_enter_load = alloc_pages(msr_list_page_order);
	vm_exit_load = alloc_pages(msr_list_page_order);
	vm_exit_store = alloc_pages(msr_list_page_order);

	vmcs_write(ENTER_MSR_LD_ADDR, (u64)vm_enter_load);
	vmcs_write(EXIT_MSR_LD_ADDR, (u64)vm_exit_load);
	vmcs_write(EXIT_MSR_ST_ADDR, (u64)vm_exit_store);

	/*
	 * VM-Enter should succeed up to the max number of MSRs per list, and
	 * should not consume junk beyond the last entry.
	 */
	populate_msr_list(vm_enter_load, byte_capacity, count);
	populate_msr_list(vm_exit_load, byte_capacity, exit_count);
	populate_msr_list(vm_exit_store, byte_capacity, exit_count);

	vmcs_write(ENT_MSR_LD_CNT, count);
	vmcs_write(EXI_MSR_LD_CNT, exit_count);
	vmcs_write(EXI_MSR_ST_CNT, exit_count);

	if (count <= max_allowed) {
		enter_guest();
		assert_exit_reason(VMX_VMCALL);
		skip_exit_vmcall();
	} else {
		u32 exit_qual;

		test_guest_state("Invalid MSR Load Count", true, count,
				 "ENT_MSR_LD_CNT");

		exit_qual = vmcs_read(EXI_QUALIFICATION);
		report(exit_qual == max_allowed + 1, "exit_qual, %u, is %u.",
		       exit_qual, max_allowed + 1);
	}

	/* Cleanup. */
	vmcs_write(ENT_MSR_LD_CNT, 0);
	vmcs_write(EXI_MSR_LD_CNT, 0);
	vmcs_write(EXI_MSR_ST_CNT, 0);
	for (i = 0; i < cleanup_count; i++) {
		enter_guest();
		skip_exit_vmcall();
	}
	free_pages_by_order(vm_enter_load, msr_list_page_order);
	free_pages_by_order(vm_exit_load, msr_list_page_order);
	free_pages_by_order(vm_exit_store, msr_list_page_order);
}

static void atomic_switch_max_msrs_test(void)
{
	atomic_switch_msrs_test(max_msr_list_size());
}

static void atomic_switch_overflow_msrs_test(void)
{
	if (test_device_enabled())
		atomic_switch_msrs_test(max_msr_list_size() + 1);
	else
		test_skip("Test is only supported on KVM");
}

static void vmx_pf_exception_test_guest(void)
{
	ac_test_run(PT_LEVEL_PML4);
}

typedef void (*invalidate_tlb_t)(void *data);

static void __vmx_pf_exception_test(invalidate_tlb_t inv_fn, void *data)
{
	u64 efer;
	struct cpuid cpuid;

	test_set_guest(vmx_pf_exception_test_guest);

	/* Intercept INVLPG when to perform TLB invalidation from L1 (this). */
	if (inv_fn)
		vmcs_set_bits(CPU_EXEC_CTRL0, CPU_INVLPG);
	else
		vmcs_clear_bits(CPU_EXEC_CTRL0, CPU_INVLPG);

	enter_guest();

	while (vmcs_read(EXI_REASON) != VMX_VMCALL) {
		switch (vmcs_read(EXI_REASON)) {
		case VMX_RDMSR:
			assert(regs.rcx == MSR_EFER);
			efer = vmcs_read(GUEST_EFER);
			regs.rdx = efer >> 32;
			regs.rax = efer & 0xffffffff;
			break;
		case VMX_WRMSR:
			assert(regs.rcx == MSR_EFER);
			efer = regs.rdx << 32 | (regs.rax & 0xffffffff);
			vmcs_write(GUEST_EFER, efer);
			break;
		case VMX_CPUID:
			cpuid = (struct cpuid) {0, 0, 0, 0};
			cpuid = raw_cpuid(regs.rax, regs.rcx);
			regs.rax = cpuid.a;
			regs.rbx = cpuid.b;
			regs.rcx = cpuid.c;
			regs.rdx = cpuid.d;
			break;
		case VMX_INVLPG:
			inv_fn(data);
			break;
		default:
			assert_msg(false,
				"Unexpected exit to L1, exit_reason: %s (0x%lx)",
				exit_reason_description(vmcs_read(EXI_REASON)),
				vmcs_read(EXI_REASON));
		}
		skip_exit_insn();
		enter_guest();
	}

	assert_exit_reason(VMX_VMCALL);
}

static void vmx_pf_exception_test(void)
{
	__vmx_pf_exception_test(NULL, NULL);
}

static void invalidate_tlb_no_vpid(void *data)
{
	/* If VPID is disabled, the TLB is flushed on VM-Enter and VM-Exit. */
}

static void vmx_pf_no_vpid_test(void)
{
	if (is_vpid_supported())
		vmcs_clear_bits(CPU_EXEC_CTRL1, CPU_VPID);

	__vmx_pf_exception_test(invalidate_tlb_no_vpid, NULL);
}

static void invalidate_tlb_invvpid_addr(void *data)
{
	invvpid(INVVPID_ALL, *(u16 *)data, vmcs_read(EXI_QUALIFICATION));
}

static void invalidate_tlb_new_vpid(void *data)
{
	u16 *vpid = data;

	/*
	 * Bump VPID to effectively flush L2's TLB from L0's perspective.
	 * Invalidate all VPIDs when the VPID wraps to zero as hardware/KVM is
	 * architecturally allowed to keep TLB entries indefinitely.
	 */
	++(*vpid);
	if (*vpid == 0) {
		++(*vpid);
		invvpid(INVVPID_ALL, 0, 0);
	}
	vmcs_write(VPID, *vpid);
}

static void __vmx_pf_vpid_test(invalidate_tlb_t inv_fn, u16 vpid)
{
	if (!is_vpid_supported())
		test_skip("VPID unsupported");

	if (!is_invvpid_supported())
		test_skip("INVVPID unsupported");

	vmcs_set_bits(CPU_EXEC_CTRL0, CPU_SECONDARY);
	vmcs_set_bits(CPU_EXEC_CTRL1, CPU_VPID);
	vmcs_write(VPID, vpid);

	__vmx_pf_exception_test(inv_fn, &vpid);
}

static void vmx_pf_invvpid_test(void)
{
	if (!is_invvpid_type_supported(INVVPID_ADDR))
		test_skip("INVVPID ADDR unsupported");

	__vmx_pf_vpid_test(invalidate_tlb_invvpid_addr, 0xaaaa);
}

static void vmx_pf_vpid_test(void)
{
	/* Need INVVPID(ALL) to flush VPIDs upon wrap/reuse. */
	if (!is_invvpid_type_supported(INVVPID_ALL))
		test_skip("INVVPID ALL unsupported");

	__vmx_pf_vpid_test(invalidate_tlb_new_vpid, 1);
}

static void vmx_l2_ac_test(void)
{
	bool hit_ac = false;

	write_cr0(read_cr0() | X86_CR0_AM);
	write_rflags(read_rflags() | X86_EFLAGS_AC);

	run_in_user(generate_usermode_ac, AC_VECTOR, 0, 0, 0, 0, &hit_ac);
	report(hit_ac, "Usermode #AC handled in L2");
	vmcall();
}

struct vmx_exception_test {
	u8 vector;
	void (*guest_code)(void);
};

struct vmx_exception_test vmx_exception_tests[] = {
	{ GP_VECTOR, generate_non_canonical_gp },
	{ UD_VECTOR, generate_ud },
	{ DE_VECTOR, generate_de },
	{ DB_VECTOR, generate_single_step_db },
	{ BP_VECTOR, generate_bp },
	{ AC_VECTOR, vmx_l2_ac_test },
};

static u8 vmx_exception_test_vector;

static void vmx_exception_handler(struct ex_regs *regs)
{
	report(regs->vector == vmx_exception_test_vector,
	       "Handling %s in L2's exception handler",
	       exception_mnemonic(vmx_exception_test_vector));
	vmcall();
}

static void handle_exception_in_l2(u8 vector)
{
	handler old_handler = handle_exception(vector, vmx_exception_handler);

	vmx_exception_test_vector = vector;

	enter_guest();
	report(vmcs_read(EXI_REASON) == VMX_VMCALL,
	       "%s handled by L2", exception_mnemonic(vector));

	handle_exception(vector, old_handler);
}

static void handle_exception_in_l1(u32 vector)
{
	u32 old_eb = vmcs_read(EXC_BITMAP);

	vmcs_write(EXC_BITMAP, old_eb | (1u << vector));

	enter_guest();

	report((vmcs_read(EXI_REASON) == VMX_EXC_NMI) &&
	       ((vmcs_read(EXI_INTR_INFO) & 0xff) == vector),
	       "%s handled by L1", exception_mnemonic(vector));

	vmcs_write(EXC_BITMAP, old_eb);
}

static void vmx_exception_test(void)
{
	struct vmx_exception_test *t;
	int i;

	for (i = 0; i < ARRAY_SIZE(vmx_exception_tests); i++) {
		t = &vmx_exception_tests[i];

		/*
		 * Override the guest code before each run even though it's the
		 * same code, the VMCS guest state needs to be reinitialized.
		 */
		test_override_guest(t->guest_code);
		handle_exception_in_l2(t->vector);

		test_override_guest(t->guest_code);
		handle_exception_in_l1(t->vector);
	}

	test_set_guest_finished();
}

#define TEST(name) { #name, .v2 = name }

/* name/init/guest_main/exit_handler/syscall_handler/guest_regs */
struct vmx_test vmx_tests[] = {
	{ "null", NULL, basic_guest_main, basic_exit_handler, NULL, {0} },
	{ "vmenter", NULL, vmenter_main, vmenter_exit_handler, NULL, {0} },
	{ "preemption timer", preemption_timer_init, preemption_timer_main,
		preemption_timer_exit_handler, NULL, {0} },
	{ "control field PAT", test_ctrl_pat_init, test_ctrl_pat_main,
		test_ctrl_pat_exit_handler, NULL, {0} },
	{ "control field EFER", test_ctrl_efer_init, test_ctrl_efer_main,
		test_ctrl_efer_exit_handler, NULL, {0} },
	{ "CR shadowing", NULL, cr_shadowing_main,
		cr_shadowing_exit_handler, NULL, {0} },
	{ "I/O bitmap", iobmp_init, iobmp_main, iobmp_exit_handler,
		NULL, {0} },
	{ "instruction intercept", insn_intercept_init, insn_intercept_main,
		insn_intercept_exit_handler, NULL, {0} },
	{ "EPT A/D disabled", ept_init, ept_main, ept_exit_handler, NULL, {0} },
	{ "EPT A/D enabled", eptad_init, eptad_main, eptad_exit_handler, NULL, {0} },
	{ "PML", pml_init, pml_main, pml_exit_handler, NULL, {0} },
	{ "interrupt", interrupt_init, interrupt_main,
		interrupt_exit_handler, NULL, {0} },
	{ "nmi_hlt", nmi_hlt_init, nmi_hlt_main,
		nmi_hlt_exit_handler, NULL, {0} },
	{ "debug controls", dbgctls_init, dbgctls_main, dbgctls_exit_handler,
		NULL, {0} },
	{ "MSR switch", msr_switch_init, msr_switch_main,
		msr_switch_exit_handler, NULL, {0}, msr_switch_entry_failure },
	{ "vmmcall", vmmcall_init, vmmcall_main, vmmcall_exit_handler, NULL, {0} },
	{ "disable RDTSCP", disable_rdtscp_init, disable_rdtscp_main,
		disable_rdtscp_exit_handler, NULL, {0} },
	{ "int3", int3_init, int3_guest_main, int3_exit_handler, NULL, {0} },
	{ "into", into_init, into_guest_main, into_exit_handler, NULL, {0} },
	{ "exit_monitor_from_l2_test", NULL, exit_monitor_from_l2_main,
		exit_monitor_from_l2_handler, NULL, {0} },
	{ "invalid_msr", invalid_msr_init, invalid_msr_main,
		invalid_msr_exit_handler, NULL, {0}, invalid_msr_entry_failure},
	/* Basic V2 tests. */
	TEST(v2_null_test),
	TEST(v2_multiple_entries_test),
	TEST(fixture_test_case1),
	TEST(fixture_test_case2),
	/* Opcode tests. */
	TEST(invvpid_test),
	/* VM-entry tests */
	TEST(vmx_controls_test),
	TEST(vmx_host_state_area_test),
	TEST(vmx_guest_state_area_test),
	TEST(vmentry_movss_shadow_test),
	TEST(vmentry_unrestricted_guest_test),
	/* APICv tests */
	TEST(vmx_eoi_bitmap_ioapic_scan_test),
	TEST(vmx_hlt_with_rvi_test),
	TEST(apic_reg_virt_test),
	TEST(virt_x2apic_mode_test),
	/* APIC pass-through tests */
	TEST(vmx_apic_passthrough_test),
	TEST(vmx_apic_passthrough_thread_test),
	TEST(vmx_apic_passthrough_tpr_threshold_test),
	TEST(vmx_init_signal_test),
	TEST(vmx_sipi_signal_test),
	/* VMCS Shadowing tests */
	TEST(vmx_vmcs_shadow_test),
	/* Regression tests */
	TEST(vmx_ldtr_test),
	TEST(vmx_cr_load_test),
	TEST(vmx_cr4_osxsave_test),
	TEST(vmx_nm_test),
	TEST(vmx_db_test),
	TEST(vmx_nmi_window_test),
	TEST(vmx_intr_window_test),
	TEST(vmx_pending_event_test),
	TEST(vmx_pending_event_hlt_test),
	TEST(vmx_store_tsc_test),
	TEST(vmx_preemption_timer_zero_test),
	TEST(vmx_preemption_timer_tf_test),
	TEST(vmx_preemption_timer_expiry_test),
	/* EPT access tests. */
	TEST(ept_access_test_not_present),
	TEST(ept_access_test_read_only),
	TEST(ept_access_test_write_only),
	TEST(ept_access_test_read_write),
	TEST(ept_access_test_execute_only),
	TEST(ept_access_test_read_execute),
	TEST(ept_access_test_write_execute),
	TEST(ept_access_test_read_write_execute),
	TEST(ept_access_test_reserved_bits),
	TEST(ept_access_test_ignored_bits),
	TEST(ept_access_test_paddr_not_present_ad_disabled),
	TEST(ept_access_test_paddr_not_present_ad_enabled),
	TEST(ept_access_test_paddr_read_only_ad_disabled),
	TEST(ept_access_test_paddr_read_only_ad_enabled),
	TEST(ept_access_test_paddr_read_write),
	TEST(ept_access_test_paddr_read_write_execute),
	TEST(ept_access_test_paddr_read_execute_ad_disabled),
	TEST(ept_access_test_paddr_read_execute_ad_enabled),
	TEST(ept_access_test_paddr_not_present_page_fault),
	TEST(ept_access_test_force_2m_page),
	/* Atomic MSR switch tests. */
	TEST(atomic_switch_max_msrs_test),
	TEST(atomic_switch_overflow_msrs_test),
	TEST(rdtsc_vmexit_diff_test),
	TEST(vmx_mtf_test),
	TEST(vmx_mtf_pdpte_test),
	TEST(vmx_pf_exception_test),
	TEST(vmx_pf_no_vpid_test),
	TEST(vmx_pf_invvpid_test),
	TEST(vmx_pf_vpid_test),
	TEST(vmx_exception_test),
	{ NULL, NULL, NULL, NULL, NULL, {0} },
};
