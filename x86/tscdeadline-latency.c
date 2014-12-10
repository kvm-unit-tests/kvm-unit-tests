/*
 * qemu command line | grep latency | cut -f 2 -d ":" > latency
 *
 * In octave:
 * load latency
 * min(list)
 * max(list)
 * mean(list)
 * hist(latency, 50)
 */

#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"
#include "msr.h"

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
u64 exptime;
int delta;
#define TABLE_SIZE 10000
u64 table[TABLE_SIZE];
volatile int table_idx;

static void tsc_deadline_timer_isr(isr_regs_t *regs)
{
    u64 now = rdtsc();
    ++tdt_count;

    if (table_idx < TABLE_SIZE && tdt_count > 1)
        table[table_idx++] = now - exptime;

    exptime = now+delta;
    wrmsr(MSR_IA32_TSCDEADLINE, now+delta);
    apic_write(APIC_EOI, 0);
}

static void start_tsc_deadline_timer(void)
{
    handle_irq(TSC_DEADLINE_TIMER_VECTOR, tsc_deadline_timer_isr);
    irq_enable();

    wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC)+delta);
    asm volatile ("nop");
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

int main()
{
    int i;

    setup_vm();
    smp_init();
    setup_idt();

    test_lapic_existence();

    mask_pic_interrupts();

    delta = 200000;
    test_tsc_deadline_timer();
    irq_enable();

    do {
        asm volatile("hlt");
    } while (table_idx < TABLE_SIZE);

    for (i = 0; i < TABLE_SIZE; i++)
        printf("latency: %d\n", table[i]);

    return report_summary();
}
