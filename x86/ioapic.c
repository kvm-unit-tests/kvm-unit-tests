#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"
#include "delay.h"

static void toggle_irq_line(unsigned line)
{
	set_irq_line(line, 1);
	set_irq_line(line, 0);
}

static void ioapic_reg_version(void)
{
	u8 version_offset;
	uint32_t data_read, data_write;

	version_offset = 0x01;
	data_read = ioapic_read_reg(version_offset);
	data_write = data_read ^ 0xffffffff;

	ioapic_write_reg(version_offset, data_write);
	report(data_read == ioapic_read_reg(version_offset),
	       "version register read only test");
}

static void ioapic_reg_id(void)
{
	u8 id_offset;
	uint32_t data_read, data_write, diff;

	id_offset = 0x0;
	data_read = ioapic_read_reg(id_offset);
	data_write = data_read ^ 0xffffffff;

	ioapic_write_reg(id_offset, data_write);

	diff = data_read ^ ioapic_read_reg(id_offset);
	report(diff == 0x0f000000, "id register only bits [24:27] writable");
}

static void ioapic_arbitration_id(void)
{
	u8 id_offset, arb_offset;
	uint32_t write;

	id_offset = 0x0;
	arb_offset = 0x2;
	write = 0x0f000000;

	ioapic_write_reg(id_offset, write);
	report(ioapic_read_reg(arb_offset) == write,
	       "arbitration register set by id");

	ioapic_write_reg(arb_offset, 0x0);
	report(ioapic_read_reg(arb_offset) == write,
	       "arbtration register read only");
}

static volatile int g_isr_76;

static void ioapic_isr_76(isr_regs_t *regs)
{
	++g_isr_76;
	eoi();
}

static void test_ioapic_edge_intr(void)
{
	handle_irq(0x76, ioapic_isr_76);
	ioapic_set_redir(0x0e, 0x76, TRIGGER_EDGE);
	toggle_irq_line(0x0e);
	asm volatile ("nop");
	report(g_isr_76 == 1, "edge triggered intr");
}

static volatile int g_isr_77;

static void ioapic_isr_77(isr_regs_t *regs)
{
	++g_isr_77;
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_level_intr(void)
{
	handle_irq(0x77, ioapic_isr_77);
	ioapic_set_redir(0x0e, 0x77, TRIGGER_LEVEL);
	set_irq_line(0x0e, 1);
	asm volatile ("nop");
	report(g_isr_77 == 1, "level triggered intr");
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
	ioapic_set_redir(0x0e, 0x78, TRIGGER_EDGE);
	ioapic_set_redir(0x0f, 0x66, TRIGGER_EDGE);
	irq_disable();
	toggle_irq_line(0x0f);
	toggle_irq_line(0x0e);
	irq_enable();
	asm volatile ("nop");
	report(g_66 && g_78 && g_66_after_78 && g_66_rip == g_78_rip,
	       "ioapic simultaneous edge interrupts");
}

static volatile int g_tmr_79 = -1;

static void ioapic_isr_79(isr_regs_t *regs)
{
	g_tmr_79 = apic_read_bit(APIC_TMR, 0x79);
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_edge_tmr(bool expected_tmr_before)
{
	int tmr_before;

	handle_irq(0x79, ioapic_isr_79);
	ioapic_set_redir(0x0e, 0x79, TRIGGER_EDGE);
	tmr_before = apic_read_bit(APIC_TMR, 0x79);
	toggle_irq_line(0x0e);
	asm volatile ("nop");
	report(tmr_before == expected_tmr_before && !g_tmr_79,
	       "TMR for ioapic edge interrupts (expected %s)",
	       expected_tmr_before ? "true" : "false");
}

static void test_ioapic_level_tmr(bool expected_tmr_before)
{
	int tmr_before;

	handle_irq(0x79, ioapic_isr_79);
	ioapic_set_redir(0x0e, 0x79, TRIGGER_LEVEL);
	tmr_before = apic_read_bit(APIC_TMR, 0x79);
	set_irq_line(0x0e, 1);
	asm volatile ("nop");
	report(tmr_before == expected_tmr_before && g_tmr_79,
	       "TMR for ioapic level interrupts (expected %s)",
	       expected_tmr_before ? "true" : "false");
}

static void toggle_irq_line_0x0e(void *data)
{
	irq_disable();
	delay(IPI_DELAY);
	toggle_irq_line(0x0e);
	irq_enable();
}

static void test_ioapic_edge_tmr_smp(bool expected_tmr_before)
{
	int tmr_before;
	int i;

	g_tmr_79 = -1;
	handle_irq(0x79, ioapic_isr_79);
	ioapic_set_redir(0x0e, 0x79, TRIGGER_EDGE);
	tmr_before = apic_read_bit(APIC_TMR, 0x79);
	on_cpu_async(1, toggle_irq_line_0x0e, 0);
	i = 0;
	while(g_tmr_79 == -1) i++;
	printf("%d iterations before interrupt received\n", i);
	report(tmr_before == expected_tmr_before && !g_tmr_79,
	       "TMR for ioapic edge interrupts (expected %s)",
	       expected_tmr_before ? "true" : "false");
}

static void set_irq_line_0x0e(void *data)
{
	irq_disable();
	delay(IPI_DELAY);
	set_irq_line(0x0e, 1);
	irq_enable();
}

static void test_ioapic_level_tmr_smp(bool expected_tmr_before)
{
	int i, tmr_before;

	g_tmr_79 = -1;
	handle_irq(0x79, ioapic_isr_79);
	ioapic_set_redir(0x0e, 0x79, TRIGGER_LEVEL);
	tmr_before = apic_read_bit(APIC_TMR, 0x79);
	on_cpu_async(1, set_irq_line_0x0e, 0);
	i = 0;
	while(g_tmr_79 == -1) i++;
	printf("%d iterations before interrupt received\n", i);
	report(tmr_before == expected_tmr_before && g_tmr_79,
	       "TMR for ioapic level interrupts (expected %s)",
	       expected_tmr_before ? "true" : "false");
}

static int g_isr_98;

static void ioapic_isr_98(isr_regs_t *regs)
{
	++g_isr_98;
	if (g_isr_98 == 1) {
		set_irq_line(0x0e, 0);
		set_irq_line(0x0e, 1);
	}
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_level_coalesce(void)
{
	handle_irq(0x98, ioapic_isr_98);
	ioapic_set_redir(0x0e, 0x98, TRIGGER_LEVEL);
	set_irq_line(0x0e, 1);
	asm volatile ("nop");
	report(g_isr_98 == 1, "coalesce simultaneous level interrupts");
}

static int g_isr_99;

static void ioapic_isr_99(isr_regs_t *regs)
{
	++g_isr_99;
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_level_sequential(void)
{
	handle_irq(0x99, ioapic_isr_99);
	ioapic_set_redir(0x0e, 0x99, TRIGGER_LEVEL);
	set_irq_line(0x0e, 1);
	set_irq_line(0x0e, 1);
	asm volatile ("nop");
	report(g_isr_99 == 2, "sequential level interrupts");
}

static volatile int g_isr_9a;

static void ioapic_isr_9a(isr_regs_t *regs)
{
	++g_isr_9a;
	if (g_isr_9a == 2)
		set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_level_retrigger(void)
{
	int i;

	handle_irq(0x9a, ioapic_isr_9a);
	ioapic_set_redir(0x0e, 0x9a, TRIGGER_LEVEL);

	asm volatile ("cli");
	set_irq_line(0x0e, 1);

	for (i = 0; i < 10; i++) {
		if (g_isr_9a == 2)
			break;

		asm volatile ("sti; hlt; cli");
	}

	asm volatile ("sti");

	report(g_isr_9a == 2, "retriggered level interrupts without masking");
}

static volatile int g_isr_81;

static void ioapic_isr_81(isr_regs_t *regs)
{
	++g_isr_81;
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_edge_mask(void)
{
	handle_irq(0x81, ioapic_isr_81);
	ioapic_set_redir(0x0e, 0x81, TRIGGER_EDGE);

	set_mask(0x0e, true);
	set_irq_line(0x0e, 1);
	set_irq_line(0x0e, 0);

	asm volatile ("nop");
	report(g_isr_81 == 0, "masked level interrupt");

	set_mask(0x0e, false);
	set_irq_line(0x0e, 1);

	asm volatile ("nop");
	report(g_isr_81 == 1, "unmasked level interrupt");
}

static volatile int g_isr_82;

static void ioapic_isr_82(isr_regs_t *regs)
{
	++g_isr_82;
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_level_mask(void)
{
	handle_irq(0x82, ioapic_isr_82);
	ioapic_set_redir(0x0e, 0x82, TRIGGER_LEVEL);

	set_mask(0x0e, true);
	set_irq_line(0x0e, 1);

	asm volatile ("nop");
	report(g_isr_82 == 0, "masked level interrupt");

	set_mask(0x0e, false);

	asm volatile ("nop");
	report(g_isr_82 == 1, "unmasked level interrupt");
}

static volatile int g_isr_83;

static void ioapic_isr_83(isr_regs_t *regs)
{
	++g_isr_83;
	set_mask(0x0e, true);
	eoi();
}

static void test_ioapic_level_retrigger_mask(void)
{
	handle_irq(0x83, ioapic_isr_83);
	ioapic_set_redir(0x0e, 0x83, TRIGGER_LEVEL);

	set_irq_line(0x0e, 1);
	asm volatile ("nop");
	set_mask(0x0e, false);
	asm volatile ("nop");
	report(g_isr_83 == 2, "retriggered level interrupts with mask");

	set_irq_line(0x0e, 0);
	set_mask(0x0e, false);
}

static volatile int g_isr_84;

static void ioapic_isr_84(isr_regs_t *regs)
{
	int line = 0xe;
	ioapic_redir_entry_t e;

	++g_isr_84;
	set_irq_line(line, 0);

	e = ioapic_read_redir(line);
	e.dest_id = 1;

	// Update only upper part of the register because we only change the
	// destination, which resides in the upper part
	ioapic_write_reg(0x10 + line * 2 + 1, ((u32 *)&e)[1]);

	eoi();
}

static void test_ioapic_self_reconfigure(void)
{
	ioapic_redir_entry_t e = {
		.vector = 0x84,
		.delivery_mode = 0,
		.dest_mode = 0,
		.dest_id = 0,
		.trig_mode = TRIGGER_LEVEL,
	};

	handle_irq(0x84, ioapic_isr_84);
	ioapic_write_redir(0xe, e);
	set_irq_line(0x0e, 1);
	e = ioapic_read_redir(0xe);
	report(g_isr_84 == 1 && e.remote_irr == 0, "Reconfigure self");
}

static volatile int g_isr_85;

static void ioapic_isr_85(isr_regs_t *regs)
{
	++g_isr_85;
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_physical_destination_mode(void)
{
	ioapic_redir_entry_t e = {
		.vector = 0x85,
		.delivery_mode = 0,
		.dest_mode = 0,
		.dest_id = 0x1,
		.trig_mode = TRIGGER_LEVEL,
	};
	handle_irq(0x85, ioapic_isr_85);
	ioapic_write_redir(0xe, e);
	set_irq_line(0x0e, 1);
	do {
		pause();
	} while(g_isr_85 != 1);
	report(g_isr_85 == 1, "ioapic physical destination mode");
}

static volatile int g_isr_86;
struct spinlock ioapic_lock;

static void ioapic_isr_86(isr_regs_t *regs)
{
	spin_lock(&ioapic_lock);
	++g_isr_86;
	spin_unlock(&ioapic_lock);
	set_irq_line(0x0e, 0);
	eoi();
}

static void test_ioapic_logical_destination_mode(void)
{
	/* Number of vcpus which are configured/set in dest_id */
	int nr_vcpus = 3;
	ioapic_redir_entry_t e = {
		.vector = 0x86,
		.delivery_mode = 0,
		.dest_mode = 1,
		.dest_id = 0xd,
		.trig_mode = TRIGGER_LEVEL,
	};
	handle_irq(0x86, ioapic_isr_86);
	ioapic_write_redir(0xe, e);
	set_irq_line(0x0e, 1);
	do {
		pause();
	} while(g_isr_86 < nr_vcpus);
	report(g_isr_86 == nr_vcpus, "ioapic logical destination mode");
}

static void update_cr3(void *cr3)
{
	write_cr3((ulong)cr3);
}

int main(void)
{
	setup_vm();
	smp_init();

	on_cpus(update_cr3, (void *)read_cr3());
	mask_pic_interrupts();

	if (enable_x2apic())
		printf("x2apic enabled\n");
	else
		printf("x2apic not detected\n");

	irq_enable();

	ioapic_reg_version();
	ioapic_reg_id();
	ioapic_arbitration_id();

	test_ioapic_edge_intr();
	test_ioapic_level_intr();
	test_ioapic_simultaneous();

	test_ioapic_level_coalesce();
	test_ioapic_level_sequential();
	test_ioapic_level_retrigger();

	test_ioapic_edge_mask();
	test_ioapic_level_mask();
	test_ioapic_level_retrigger_mask();

	test_ioapic_edge_tmr(false);
	test_ioapic_level_tmr(false);
	test_ioapic_level_tmr(true);
	test_ioapic_edge_tmr(true);

	if (cpu_count() > 1)
		test_ioapic_physical_destination_mode();
	if (cpu_count() > 3)
		test_ioapic_logical_destination_mode();

	if (cpu_count() > 1) {
		test_ioapic_edge_tmr_smp(false);
		test_ioapic_level_tmr_smp(false);
		test_ioapic_level_tmr_smp(true);
		test_ioapic_edge_tmr_smp(true);

		test_ioapic_self_reconfigure();
	}

	return report_summary();
}
