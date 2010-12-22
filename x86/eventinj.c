#include "libcflat.h"
#include "processor.h"
#include "vm.h"
#include "desc.h"
#include "isr.h"
#include "apic.h"
#include "apic-defs.h"

#ifdef __x86_64__
#  define R "r"
#else
#  define R "e"
#endif

static int g_fail;
static int g_tests;

static inline void io_delay(void)
{
}

static inline void outl(int addr, int val)
{
        asm volatile ("outl %1, %w0" : : "d" (addr), "a" (val));
}

static void report(const char *msg, int pass)
{
    ++g_tests;
    printf("%s: %s\n", msg, (pass ? "PASS" : "FAIL"));
    if (!pass)
        ++g_fail;
}

void apic_self_ipi(u8 v)
{
	apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED |
		       APIC_INT_ASSERT | v, 0);
}

void apic_self_nmi(void)
{
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, 0);
}

static void eoi(void)
{
    apic_write(APIC_EOI, 0);
}

#define flush_phys_addr(__s) outl(0xe4, __s)
#define flush_stack() do {						\
		int __l;						\
		flush_phys_addr(virt_to_phys(&__l));			\
	} while (0)

extern char isr_iret_ip[];

static void flush_idt_page()
{
	struct descriptor_table_ptr ptr;
	sidt(&ptr);
	flush_phys_addr(virt_to_phys((void*)ptr.base));
}

static volatile unsigned int test_divider;
static volatile int test_count;

#ifndef __x86_64__
ulong stack_phys;
void *stack_va;

static void pf_tss(void)
{
start:
	printf("PF running\n");
	install_pte(phys_to_virt(read_cr3()), 1, stack_va,
		    stack_phys | PTE_PRESENT | PTE_WRITE, 0);
	invlpg(stack_va);
	asm volatile ("iret");
	goto start;
}

static void of_isr(struct ex_regs *r)
{
	printf("OF isr running\n");
	test_count++;
}

static void np_isr(struct ex_regs *r)
{
	printf("NP isr running %x err=%x\n", r->rip, r->error_code);
	set_idt_sel(33, read_cs());
	test_count++;
}
#endif

static void de_isr(struct ex_regs *r)
{
	printf("DE isr running divider is %d\n", test_divider);
	test_divider = 10;
}

static void bp_isr(struct ex_regs *r)
{
	printf("BP isr running\n");
	test_count++;
}

static void nested_nmi_isr(struct ex_regs *r)
{
	printf("Nested NMI isr running rip=%x\n", r->rip);

	if (r->rip != (ulong)&isr_iret_ip)
		test_count++;
}
static void nmi_isr(struct ex_regs *r)
{
	printf("NMI isr running %x\n", &isr_iret_ip);
	test_count++;
	handle_exception(2, nested_nmi_isr);
	printf("Try send nested NMI to itself\n");
	apic_self_nmi();
	io_delay();
	printf("After nested NMI to itself\n");
}

static void tirq0(isr_regs_t *r)
{
	printf("irq0 running\n");
	if (test_count != 0)
		test_count++;
	eoi();
}

static void tirq1(isr_regs_t *r)
{
	printf("irq1 running\n");
	test_count++;
	eoi();
}

ulong saved_stack;

#define switch_stack(S) do {						\
		asm volatile ("mov %%" R "sp, %0":"=r"(saved_stack));	\
		asm volatile ("mov %0, %%" R "sp"::"r"(S));		\
	} while(0)

#define restore_stack() do {						\
		asm volatile ("mov %0, %%" R "sp"::"r"(saved_stack));	\
	} while(0)

int main()
{
	unsigned int res;
	ulong *pt, *cr3, i;

	setup_vm();
	setup_idt();
	setup_gdt();
	setup_tss32();

	handle_irq(32, tirq0);
	handle_irq(33, tirq1);

	/* generate HW exception that will fault on IDT and stack */
	handle_exception(0, de_isr);
	printf("Try to divide by 0\n");
	flush_idt_page();
	flush_stack();
	asm volatile ("divl %3": "=a"(res)
		      : "d"(0), "a"(1500), "m"(test_divider));
	printf("Result is %d\n", res);
	report("DE exception", res == 150);

	/* generate soft exception (BP) that will fault on IDT and stack */
	test_count = 0;
	handle_exception(3, bp_isr);
	printf("Try int 3\n");
	flush_idt_page();
	flush_stack();
	asm volatile ("int $3");
	printf("After int 3\n");
	report("BP exception", test_count == 1);

#ifndef __x86_64__
	/* generate soft exception (OF) that will fault on IDT */
	test_count = 0;
	handle_exception(4, of_isr);
	flush_idt_page();
	printf("Try into\n");
	asm volatile ("addb $127, %b0\ninto"::"a"(127));
	printf("After into\n");
	report("OF exception", test_count == 1);

	/* generate soft exception (OF) using two bit instruction that will
	   fault on IDT */
	test_count = 0;
	handle_exception(4, of_isr);
	flush_idt_page();
	printf("Try into\n");
	asm volatile ("addb $127, %b0\naddr16 into"::"a"(127));
	printf("After into\n");
	report("2 byte OF exception", test_count == 1);
#endif

	/* generate HW interrupt that will fault on IDT */
	test_count = 0;
	flush_idt_page();
	printf("Try send vec 33 to itself\n");
	irq_enable();
	apic_self_ipi(33);
	io_delay();
	irq_disable();
	printf("After vec 33 to itself\n");
	report("vec 33", test_count == 1);

	/* generate soft interrupt that will fault on IDT and stack */
	test_count = 0;
	flush_idt_page();
	printf("Try int $33\n");
	flush_stack();
	asm volatile ("int $33");
	printf("After int $33\n");
	report("int $33", test_count == 1);

	/* Inject two HW interrupt than open iterrupt windows. Both interrupt
	   will fault on IDT access */
	test_count = 0;
	flush_idt_page();
	printf("Try send vec 32 and 33 to itself\n");
	apic_self_ipi(32);
	apic_self_ipi(33);
	io_delay();
	irq_enable();
	asm volatile("nop");
	irq_disable();
	printf("After vec 32 and 33 to itself\n");
	report("vec 32/33", test_count == 2);


	/* Inject HW interrupt, do sti and than (while in irq shadow) inject
	   soft interrupt. Fault during soft interrupt. Soft interrup shoud be
	   handled before HW interrupt */
	test_count = 0;
	flush_idt_page();
	printf("Try send vec 32 and int $33\n");
	apic_self_ipi(32);
	flush_stack();
	io_delay();
	irq_enable();
	asm volatile ("int $33");
	irq_disable();
	printf("After vec 32 and int $33\n");
	report("vec 32/int $33", test_count == 2);

	/* test that TPR is honored */
	test_count = 0;
	handle_irq(62, tirq1);
	flush_idt_page();
	printf("Try send vec 33 and 62 and mask one with TPR\n");
	apic_write(APIC_TASKPRI, 0xf << 4);
	irq_enable();
	apic_self_ipi(32);
	apic_self_ipi(62);
	io_delay();
	apic_write(APIC_TASKPRI, 0x2 << 4);
	printf("After 33/62 TPR test\n");
	report("TPR", test_count == 1);
	apic_write(APIC_TASKPRI, 0x0);
	while(test_count != 2); /* wait for second irq */
	irq_disable();

#ifndef __x86_64__
	/* test fault durint NP delivery */
	printf("Before NP test\n");
	test_count = 0;
	handle_exception(11, np_isr);
	set_idt_sel(33, NP_SEL);
	flush_idt_page();
	flush_stack();
	asm volatile ("int $33");
	printf("After int33\n");
	report("NP exception", test_count == 2);
#endif

	/* generate NMI that will fault on IDT */
	test_count = 0;
	handle_exception(2, nmi_isr);
	flush_idt_page();
	printf("Try send NMI to itself\n");
	apic_self_nmi();
	printf("After NMI to itself\n");
	/* this is needed on VMX without NMI window notificatoin.
	   Interrupt windows is used instead, so let pending NMI
	   to be injected */
	irq_enable();
	asm volatile ("nop");
	irq_disable();
	report("NMI", test_count == 2);

#ifndef __x86_64__
	stack_phys = (ulong)virt_to_phys(alloc_page());
	stack_va = alloc_vpage();

	/* Generate DE and PF exceptions serially */
	test_divider = 0;
	set_intr_task_gate(14, pf_tss);
	handle_exception(0, de_isr);
	printf("Try to divide by 0\n");
	/* install read only pte */
	install_pte(phys_to_virt(read_cr3()), 1, stack_va,
		    stack_phys | PTE_PRESENT, 0);
	invlpg(stack_va);
	flush_phys_addr(stack_phys);
	switch_stack(stack_va + 4095);
	flush_idt_page();
	asm volatile ("divl %3": "=a"(res)
		      : "d"(0), "a"(1500), "m"(test_divider));
	restore_stack();
	printf("Result is %d\n", res);
	report("DE PF exceptions", res == 150);

	/* Generate NP and PF exceptions serially */
	printf("Before NP test\n");
	test_count = 0;
	set_intr_task_gate(14, pf_tss);
	handle_exception(11, np_isr);
	set_idt_sel(33, NP_SEL);
	/* install read only pte */
	install_pte(phys_to_virt(read_cr3()), 1, stack_va,
		    stack_phys | PTE_PRESENT, 0);
	invlpg(stack_va);
	flush_idt_page();
	flush_phys_addr(stack_phys);
	switch_stack(stack_va + 4095);
	asm volatile ("int $33");
	restore_stack();
	printf("After int33\n");
	report("NP PF exceptions", test_count == 2);
#endif

	pt = alloc_page();
	cr3 = (void*)read_cr3();
	memset(pt, 0, 4096);
	/* use shadowed stack during interrupt delivery */
	for (i = 0; i < 4096/sizeof(ulong); i++) {
		if (!cr3[i]) {
			cr3[i] = virt_to_phys(pt) | PTE_PRESENT | PTE_WRITE;
			pt[0] = virt_to_phys(pt) | PTE_PRESENT | PTE_WRITE;
#ifndef __x86_64__
			((ulong*)(i<<22))[1] = 0;
#else
			((ulong*)(i<<39))[1] = 0;
#endif
			write_cr3(virt_to_phys(cr3));
			break;
		}
	}
	test_count = 0;
	printf("Try int 33 with shadowed stack\n");
	switch_stack(((char*)pt) + 4095);
	asm volatile("int $33");
	restore_stack();
	printf("After int 33 with shadowed stack\n");
	report("int 33 with shadowed stack", test_count == 1);

	printf("\nsummary: %d tests, %d failures\n", g_tests, g_fail);

	return g_fail != 0;
}
