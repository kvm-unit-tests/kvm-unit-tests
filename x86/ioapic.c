#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"

#define EDGE_TRIGGERED 0
#define LEVEL_TRIGGERED 1

static void set_ioapic_redir(unsigned line, unsigned vec, unsigned trig_mode)
{
	ioapic_redir_entry_t e = {
		.vector = vec,
		.delivery_mode = 0,
		.trig_mode = trig_mode,
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

static volatile int g_isr_77;

static void ioapic_isr_77(isr_regs_t *regs)
{
	++g_isr_77;
	eoi();
}

static void test_ioapic_intr(void)
{
	handle_irq(0x77, ioapic_isr_77);
	set_ioapic_redir(0x0e, 0x77, EDGE_TRIGGERED);
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
	set_ioapic_redir(0x0e, 0x78, EDGE_TRIGGERED);
	set_ioapic_redir(0x0f, 0x66, EDGE_TRIGGERED);
	irq_disable();
	toggle_irq_line(0x0f);
	toggle_irq_line(0x0e);
	irq_enable();
	asm volatile ("nop");
	report("ioapic simultaneous interrupt",
		g_66 && g_78 && g_66_after_78 && g_66_rip == g_78_rip);
}

int main(void)
{
	setup_vm();
	smp_init();
	setup_idt();

	mask_pic_interrupts();
	enable_apic();

	irq_enable();

	test_ioapic_intr();
	test_ioapic_simultaneous();

	return report_summary();
}
