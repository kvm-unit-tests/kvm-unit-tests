#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"

typedef struct {
    ulong regs[sizeof(ulong)*2];
    ulong func;
    ulong rip;
    ulong cs;
    ulong rflags;
} isr_regs_t;

#ifdef __x86_64__
#  define R "r"
#else
#  define R "e"
#endif

extern char isr_entry_point[];

asm (
    "isr_entry_point: \n"
#ifdef __x86_64__
    "push %r15 \n\t"
    "push %r14 \n\t"
    "push %r13 \n\t"
    "push %r12 \n\t"
    "push %r11 \n\t"
    "push %r10 \n\t"
    "push %r9  \n\t"
    "push %r8  \n\t"
#endif
    "push %"R "di \n\t"
    "push %"R "si \n\t"
    "push %"R "bp \n\t"
    "push %"R "sp \n\t"
    "push %"R "bx \n\t"
    "push %"R "dx \n\t"
    "push %"R "cx \n\t"
    "push %"R "ax \n\t"
#ifdef __x86_64__
    "mov %rsp, %rdi \n\t"
    "callq *8*16(%rsp) \n\t"
#else
    "push %esp \n\t"
    "calll *4+4*8(%esp) \n\t"
    "add $4, %esp \n\t"
#endif
    "pop %"R "ax \n\t"
    "pop %"R "cx \n\t"
    "pop %"R "dx \n\t"
    "pop %"R "bx \n\t"
    "pop %"R "bp \n\t"
    "pop %"R "bp \n\t"
    "pop %"R "si \n\t"
    "pop %"R "di \n\t"
#ifdef __x86_64__
    "pop %r8  \n\t"
    "pop %r9  \n\t"
    "pop %r10 \n\t"
    "pop %r11 \n\t"
    "pop %r12 \n\t"
    "pop %r13 \n\t"
    "pop %r14 \n\t"
    "pop %r15 \n\t"
#endif
#ifdef __x86_64__
    "add $8, %rsp \n\t"
    "iretq \n\t"
#else
    "add $4, %esp \n\t"
    "iretl \n\t"
#endif
    );

static int g_fail;
static int g_tests;

static void report(const char *msg, int pass)
{
    ++g_tests;
    printf("%s: %s\n", msg, (pass ? "PASS" : "FAIL"));
    if (!pass)
        ++g_fail;
}

static void test_lapic_existence(void)
{
    u32 lvr;

    lvr = apic_read(APIC_LVR);
    printf("apic version: %x\n", lvr);
    report("apic existence", (u16)lvr == 0x14);
}

#define MSR_APIC_BASE 0x0000001b

void test_enable_x2apic(void)
{
    if (enable_x2apic()) {
        printf("x2apic enabled\n");
    } else {
        printf("x2apic not detected\n");
    }
}

static void handle_irq(unsigned vec, void (*func)(isr_regs_t *regs))
{
    u8 *thunk = vmalloc(50);

    set_idt_entry(vec, thunk, 0);

#ifdef __x86_64__
    /* sub $8, %rsp */
    *thunk++ = 0x48; *thunk++ = 0x83; *thunk++ = 0xec; *thunk++ = 0x08;
    /* mov $func_low, %(rsp) */
    *thunk++ = 0xc7; *thunk++ = 0x04; *thunk++ = 0x24;
    *(u32 *)thunk = (ulong)func; thunk += 4;
    /* mov $func_high, %(rsp+4) */
    *thunk++ = 0xc7; *thunk++ = 0x44; *thunk++ = 0x24; *thunk++ = 0x04;
    *(u32 *)thunk = (ulong)func >> 32; thunk += 4;
    /* jmp isr_entry_point */
    *thunk ++ = 0xe9;
    *(u32 *)thunk = (ulong)isr_entry_point - (ulong)(thunk + 4);
#else
    /* push $func */
    *thunk++ = 0x68;
    *(u32 *)thunk = (ulong)func;
    /* jmp isr_entry_point */
    *thunk ++ = 0xe9;
    *(u32 *)thunk = (ulong)isr_entry_point - (ulong)(thunk + 4);
#endif
}

static void irq_disable(void)
{
    asm volatile("cli");
}

static void irq_enable(void)
{
    asm volatile("sti");
}

static void eoi(void)
{
    apic_write(APIC_EOI, 0);
}

static int ipi_count;

static void self_ipi_isr(isr_regs_t *regs)
{
    ++ipi_count;
    eoi();
}

static void test_self_ipi(void)
{
    int vec = 0xf1;

    handle_irq(vec, self_ipi_isr);
    irq_enable();
    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED | vec,
                   0);
    asm volatile ("nop");
    report("self ipi", ipi_count == 1);
}

static void set_ioapic_redir(unsigned line, unsigned vec)
{
    ioapic_redir_entry_t e = {
        .vector = vec,
        .delivery_mode = 0,
        .trig_mode = 0,
    };

    ioapic_write_redir(line, e);
}

static void set_irq_line(unsigned line, int val)
{
    asm volatile("out %0, %1" : : "a"((u8)val), "d"((u16)(0x2000 + line)));
}

static void toggle_irq_line(unsigned line)
{
    set_irq_line(line, 1);
    set_irq_line(line, 0);
}

static int g_isr_77;

static void ioapic_isr_77(isr_regs_t *regs)
{
    ++g_isr_77;
    eoi();
}

static void test_ioapic_intr(void)
{
    handle_irq(0x77, ioapic_isr_77);
    set_ioapic_redir(0x10, 0x77);
    toggle_irq_line(0x10);
    asm volatile ("nop");
    report("ioapic interrupt", g_isr_77 == 1);
}

static int g_78, g_66, g_66_after_78;
static ulong g_66_rip, g_78_rip;

static void ioapic_isr_78(isr_regs_t *regs)
{
    ++g_78;
    g_78_rip = regs->rip;
    eoi();
}

static void ioapic_isr_66(isr_regs_t *regs)
{
    ++g_66;
    if (g_78)
        ++g_66_after_78;
    g_66_rip = regs->rip;
    eoi();
}

static void test_ioapic_simultaneous(void)
{
    handle_irq(0x78, ioapic_isr_78);
    handle_irq(0x66, ioapic_isr_66);
    set_ioapic_redir(0x10, 0x78);
    set_ioapic_redir(0x11, 0x66);
    irq_disable();
    toggle_irq_line(0x11);
    toggle_irq_line(0x10);
    irq_enable();
    asm volatile ("nop");
    report("ioapic simultaneous interrupt",
           g_66 && g_78 && g_66_after_78 && g_66_rip == g_78_rip);
}

volatile int nmi_counter_private, nmi_counter, nmi_hlt_counter, sti_loop_active;

void sti_nop(char *p)
{
    asm volatile (
		  ".globl post_sti \n\t"
		  "sti \n"
		  /*
		   * vmx won't exit on external interrupt if blocked-by-sti,
		   * so give it a reason to exit by accessing an unmapped page.
		   */
		  "post_sti: testb $0, %0 \n\t"
		  "nop \n\t"
		  "cli"
		  : : "m"(*p)
		  );
    nmi_counter = nmi_counter_private;
}

static void sti_loop(void *ignore)
{
    unsigned k = 0;

    while (sti_loop_active) {
	sti_nop((char *)(ulong)((k++ * 4096) % (128 * 1024 * 1024)));
    }
}

static void nmi_handler(isr_regs_t *regs)
{
    extern void post_sti(void);
    ++nmi_counter_private;
    nmi_hlt_counter += regs->rip == (ulong)post_sti;
}

static void update_cr3(void *cr3)
{
    write_cr3((ulong)cr3);
}

static void test_sti_nmi(void)
{
    unsigned old_counter;

    if (cpu_count() < 2) {
	return;
    }

    handle_irq(2, nmi_handler);
    on_cpu(1, update_cr3, (void *)read_cr3());

    sti_loop_active = 1;
    on_cpu_async(1, sti_loop, 0);
    while (nmi_counter < 30000) {
	old_counter = nmi_counter;
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, 1);
	while (nmi_counter == old_counter) {
	    ;
	}
    }
    sti_loop_active = 0;
    report("nmi-after-sti", nmi_hlt_counter == 0);
}

int main()
{
    setup_vm();
    smp_init();
    setup_idt();

    test_lapic_existence();

    mask_pic_interrupts();
    enable_apic();
    test_enable_x2apic();

    test_self_ipi();

    test_ioapic_intr();
    test_ioapic_simultaneous();
    test_sti_nmi();

    printf("\nsummary: %d tests, %d failures\n", g_tests, g_fail);

    return g_fail != 0;
}
