#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"

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

#define TSC_DEADLINE_TIMER_MODE (2 << 17)
#define TSC_DEADLINE_TIMER_VECTOR 0xef
#define MSR_IA32_TSC            0x00000010
#define MSR_IA32_TSCDEADLINE    0x000006e0

static int tdt_count;

static void tsc_deadline_timer_isr(isr_regs_t *regs)
{
    ++tdt_count;
}

static void start_tsc_deadline_timer(void)
{
    handle_irq(TSC_DEADLINE_TIMER_VECTOR, tsc_deadline_timer_isr);
    irq_enable();

    wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
    asm volatile ("nop");
    report("tsc deadline timer", tdt_count == 1);
}

static int enable_tsc_deadline_timer(void)
{
    uint32_t lvtt;

    if (cpuid(1).c & (1 << 24)) {
        lvtt = TSC_DEADLINE_TIMER_MODE | TSC_DEADLINE_TIMER_VECTOR;
        apic_write(APIC_LVTT, lvtt);
        start_tsc_deadline_timer();
        return 1;
    } else {
        return 0;
    }
}

static void test_tsc_deadline_timer(void)
{
    if(enable_tsc_deadline_timer()) {
        printf("tsc deadline timer enabled\n");
    } else {
        printf("tsc deadline timer not detected\n");
    }
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
    set_ioapic_redir(0x0e, 0x77);
    toggle_irq_line(0x0e);
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
    set_ioapic_redir(0x0e, 0x78);
    set_ioapic_redir(0x0f, 0x66);
    irq_disable();
    toggle_irq_line(0x0f);
    toggle_irq_line(0x0e);
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

static volatile bool nmi_done, nmi_flushed;
static volatile int nmi_received;
static volatile int cpu0_nmi_ctr1, cpu1_nmi_ctr1;
static volatile int cpu0_nmi_ctr2, cpu1_nmi_ctr2;

static void multiple_nmi_handler(isr_regs_t *regs)
{
    ++nmi_received;
}

static void kick_me_nmi(void *blah)
{
    while (!nmi_done) {
	++cpu1_nmi_ctr1;
	while (cpu1_nmi_ctr1 != cpu0_nmi_ctr1 && !nmi_done) {
	    pause();
	}
	if (nmi_done) {
	    return;
	}
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, 0);
	/* make sure the NMI has arrived by sending an IPI after it */
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_INT_ASSERT
		       | 0x44, 0);
	++cpu1_nmi_ctr2;
	while (cpu1_nmi_ctr2 != cpu0_nmi_ctr2 && !nmi_done) {
	    pause();
	}
    }
}

static void flush_nmi(isr_regs_t *regs)
{
    nmi_flushed = true;
    apic_write(APIC_EOI, 0);
}

static void test_multiple_nmi(void)
{
    int i;
    bool ok = true;

    if (cpu_count() < 2) {
	return;
    }

    sti();
    handle_irq(2, multiple_nmi_handler);
    handle_irq(0x44, flush_nmi);
    on_cpu_async(1, kick_me_nmi, 0);
    for (i = 0; i < 1000000; ++i) {
	nmi_flushed = false;
	nmi_received = 0;
	++cpu0_nmi_ctr1;
	while (cpu1_nmi_ctr1 != cpu0_nmi_ctr1) {
	    pause();
	}
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_NMI | APIC_INT_ASSERT, 0);
	while (!nmi_flushed) {
	    pause();
	}
	if (nmi_received != 2) {
	    ok = false;
	    break;
	}
	++cpu0_nmi_ctr2;
	while (cpu1_nmi_ctr2 != cpu0_nmi_ctr2) {
	    pause();
	}
    }
    nmi_done = true;
    report("multiple nmi", ok);
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
    test_multiple_nmi();

    test_tsc_deadline_timer();

    printf("\nsummary: %d tests, %d failures\n", g_tests, g_fail);

    return g_fail != 0;
}
