#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"
#include "msr.h"
#include "atomic.h"

#define MAX_TPR			0xf

static void test_lapic_existence(void)
{
    u32 lvr;

    lvr = apic_read(APIC_LVR);
    printf("apic version: %x\n", lvr);
    report("apic existence", (u16)lvr == 0x14);
}

#define TSC_DEADLINE_TIMER_VECTOR 0xef
#define BROADCAST_VECTOR 0xcf

static int tdt_count;

static void tsc_deadline_timer_isr(isr_regs_t *regs)
{
    ++tdt_count;
    eoi();
}

static void __test_tsc_deadline_timer(void)
{
    handle_irq(TSC_DEADLINE_TIMER_VECTOR, tsc_deadline_timer_isr);
    irq_enable();

    wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
    asm volatile ("nop");
    report("tsc deadline timer", tdt_count == 1);
    report("tsc deadline timer clearing", rdmsr(MSR_IA32_TSCDEADLINE) == 0);
}

static int enable_tsc_deadline_timer(void)
{
    uint32_t lvtt;

    if (cpuid(1).c & (1 << 24)) {
        lvtt = APIC_LVT_TIMER_TSCDEADLINE | TSC_DEADLINE_TIMER_VECTOR;
        apic_write(APIC_LVTT, lvtt);
        return 1;
    } else {
        return 0;
    }
}

static void test_tsc_deadline_timer(void)
{
    if(enable_tsc_deadline_timer()) {
        __test_tsc_deadline_timer();
    } else {
        report_skip("tsc deadline timer not detected");
    }
}

static void do_write_apicbase(void *data)
{
    wrmsr(MSR_IA32_APICBASE, *(u64 *)data);
}

static bool test_write_apicbase_exception(u64 data)
{
    return test_for_exception(GP_VECTOR, do_write_apicbase, &data);
}

static void test_enable_x2apic(void)
{
    u64 orig_apicbase = rdmsr(MSR_IA32_APICBASE);
    u64 apicbase;

    if (enable_x2apic()) {
        printf("x2apic enabled\n");

        apicbase = orig_apicbase & ~(APIC_EN | APIC_EXTD);
        report("x2apic enabled to invalid state",
               test_write_apicbase_exception(apicbase | APIC_EXTD));
        report("x2apic enabled to apic enabled",
               test_write_apicbase_exception(apicbase | APIC_EN));

        report("x2apic enabled to disabled state",
               !test_write_apicbase_exception(apicbase | 0));
        report("disabled to invalid state",
               test_write_apicbase_exception(apicbase | APIC_EXTD));
        report("disabled to x2apic enabled",
               test_write_apicbase_exception(apicbase | APIC_EN | APIC_EXTD));

        report("apic disabled to apic enabled",
               !test_write_apicbase_exception(apicbase | APIC_EN));
        report("apic enabled to invalid state",
               test_write_apicbase_exception(apicbase | APIC_EXTD));

        if (orig_apicbase & APIC_EXTD)
            enable_x2apic();
        else
            reset_apic();

        /*
         * Disabling the APIC resets various APIC registers, restore them to
         * their desired values.
         */
        apic_write(APIC_SPIV, 0x1ff);
    } else {
        printf("x2apic not detected\n");

        report("enable unsupported x2apic",
               test_write_apicbase_exception(APIC_EN | APIC_EXTD));
    }
}

static void verify_disabled_apic_mmio(void)
{
    volatile u32 *lvr = (volatile u32 *)(APIC_DEFAULT_PHYS_BASE + APIC_LVR);
    volatile u32 *tpr = (volatile u32 *)(APIC_DEFAULT_PHYS_BASE + APIC_TASKPRI);
    u32 cr8 = read_cr8();

    memset((void *)APIC_DEFAULT_PHYS_BASE, 0xff, PAGE_SIZE);
    report("*0xfee00030: %x", *lvr == ~0, *lvr);
    report("CR8: %lx", read_cr8() == cr8, read_cr8());
    write_cr8(cr8 ^ MAX_TPR);
    report("CR8: %lx", read_cr8() == (cr8 ^ MAX_TPR), read_cr8());
    report("*0xfee00080: %x", *tpr == ~0, *tpr);
    write_cr8(cr8);
}

static void test_apic_disable(void)
{
    volatile u32 *lvr = (volatile u32 *)(APIC_DEFAULT_PHYS_BASE + APIC_LVR);
    volatile u32 *tpr = (volatile u32 *)(APIC_DEFAULT_PHYS_BASE + APIC_TASKPRI);
    u64 orig_apicbase = rdmsr(MSR_IA32_APICBASE);
    u32 apic_version = apic_read(APIC_LVR);
    u32 cr8 = read_cr8();

    report_prefix_push("apic_disable");
    assert_msg(orig_apicbase & APIC_EN, "APIC not enabled.");

    disable_apic();
    report("Local apic disabled", !(rdmsr(MSR_IA32_APICBASE) & APIC_EN));
    report("CPUID.1H:EDX.APIC[bit 9] is clear", !(cpuid(1).d & (1 << 9)));
    verify_disabled_apic_mmio();

    reset_apic();
    apic_write(APIC_SPIV, 0x1ff);
    report("Local apic enabled in xAPIC mode",
	   (rdmsr(MSR_IA32_APICBASE) & (APIC_EN | APIC_EXTD)) == APIC_EN);
    report("CPUID.1H:EDX.APIC[bit 9] is set", cpuid(1).d & (1 << 9));
    report("*0xfee00030: %x", *lvr == apic_version, *lvr);
    report("*0xfee00080: %x", *tpr == cr8, *tpr);
    write_cr8(cr8 ^ MAX_TPR);
    report("*0xfee00080: %x", *tpr == (cr8 ^ MAX_TPR) << 4, *tpr);
    write_cr8(cr8);

    if (enable_x2apic()) {
	apic_write(APIC_SPIV, 0x1ff);
	report("Local apic enabled in x2APIC mode",
	   (rdmsr(MSR_IA32_APICBASE) & (APIC_EN | APIC_EXTD)) ==
	   (APIC_EN | APIC_EXTD));
	report("CPUID.1H:EDX.APIC[bit 9] is set", cpuid(1).d & (1 << 9));
	verify_disabled_apic_mmio();
	if (!(orig_apicbase & APIC_EXTD))
	    reset_apic();
    }
    report_prefix_pop();
}

#define ALTERNATE_APIC_BASE	0x42000000

static void test_apicbase(void)
{
    u64 orig_apicbase = rdmsr(MSR_IA32_APICBASE);
    u32 lvr = apic_read(APIC_LVR);
    u64 value;

    wrmsr(MSR_IA32_APICBASE, orig_apicbase & ~(APIC_EN | APIC_EXTD));
    wrmsr(MSR_IA32_APICBASE, ALTERNATE_APIC_BASE | APIC_BSP | APIC_EN);

    report_prefix_push("apicbase");

    report("relocate apic",
           *(volatile u32 *)(ALTERNATE_APIC_BASE + APIC_LVR) == lvr);

    value = orig_apicbase | (1UL << cpuid_maxphyaddr());
    report("reserved physaddr bits",
           test_for_exception(GP_VECTOR, do_write_apicbase, &value));

    value = orig_apicbase | 1;
    report("reserved low bits",
           test_for_exception(GP_VECTOR, do_write_apicbase, &value));

    wrmsr(MSR_IA32_APICBASE, orig_apicbase);
    apic_write(APIC_SPIV, 0x1ff);

    report_prefix_pop();
}

static void do_write_apic_id(void *id)
{
    apic_write(APIC_ID, *(u32 *)id);
}

static void __test_apic_id(void * unused)
{
    u32 id, newid;
    u8  initial_xapic_id = cpuid(1).b >> 24;
    u32 initial_x2apic_id = cpuid(0xb).d;
    bool x2apic_mode = rdmsr(MSR_IA32_APICBASE) & APIC_EXTD;

    if (x2apic_mode)
        reset_apic();

    id = apic_id();
    report("xapic id matches cpuid", initial_xapic_id == id);

    newid = (id + 1) << 24;
    report("writeable xapic id",
            !test_for_exception(GP_VECTOR, do_write_apic_id, &newid) &&
            id + 1 == apic_id());

    if (!enable_x2apic())
        goto out;

    report("non-writeable x2apic id",
            test_for_exception(GP_VECTOR, do_write_apic_id, &newid));
    report("sane x2apic id", initial_xapic_id == (apic_id() & 0xff));

    /* old QEMUs do not set initial x2APIC ID */
    report("x2apic id matches cpuid",
           initial_xapic_id == (initial_x2apic_id & 0xff) &&
           initial_x2apic_id == apic_id());

out:
    reset_apic();

    report("correct xapic id after reset", initial_xapic_id == apic_id());

    /* old KVMs do not reset xAPIC ID */
    if (id != apic_id())
        apic_write(APIC_ID, id << 24);

    if (x2apic_mode)
        enable_x2apic();
}

static void test_apic_id(void)
{
    if (cpu_count() < 2)
        return;

    on_cpu(1, __test_apic_id, NULL);
}

static int ipi_count;

static void self_ipi_isr(isr_regs_t *regs)
{
    ++ipi_count;
    eoi();
}

static void test_self_ipi(void)
{
    u64 start = rdtsc();
    int vec = 0xf1;

    handle_irq(vec, self_ipi_isr);
    irq_enable();
    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED | vec,
                   0);

    do {
        pause();
    } while (rdtsc() - start < 1000000000 && ipi_count == 0);

    report("self ipi", ipi_count == 1);
}

volatile int nmi_counter_private, nmi_counter, nmi_hlt_counter, sti_loop_active;

static void sti_nop(char *p)
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

static volatile int lvtt_counter = 0;

static void lvtt_handler(isr_regs_t *regs)
{
    lvtt_counter++;
    eoi();
}

static void test_apic_timer_one_shot(void)
{
    uint64_t tsc1, tsc2;
    static const uint32_t interval = 0x10000;

#define APIC_LVT_TIMER_VECTOR    (0xee)

    handle_irq(APIC_LVT_TIMER_VECTOR, lvtt_handler);
    irq_enable();

    /* One shot mode */
    apic_write(APIC_LVTT, APIC_LVT_TIMER_ONESHOT |
               APIC_LVT_TIMER_VECTOR);
    /* Divider == 1 */
    apic_write(APIC_TDCR, 0x0000000b);

    tsc1 = rdtsc();
    /* Set "Initial Counter Register", which starts the timer */
    apic_write(APIC_TMICT, interval);
    while (!lvtt_counter);
    tsc2 = rdtsc();

    /*
     * For LVT Timer clock, SDM vol 3 10.5.4 says it should be
     * derived from processor's bus clock (IIUC which is the same
     * as TSC), however QEMU seems to be using nanosecond. In all
     * cases, the following should satisfy on all modern
     * processors.
     */
    report("APIC LVT timer one shot", (lvtt_counter == 1) &&
           (tsc2 - tsc1 >= interval));
}

static atomic_t broadcast_counter;

static void broadcast_handler(isr_regs_t *regs)
{
	atomic_inc(&broadcast_counter);
	eoi();
}

static bool broadcast_received(unsigned ncpus)
{
	unsigned counter;
	u64 start = rdtsc();

	do {
		counter = atomic_read(&broadcast_counter);
		if (counter >= ncpus)
			break;
		pause();
	} while (rdtsc() - start < 1000000000);

	atomic_set(&broadcast_counter, 0);

	return counter == ncpus;
}

static void test_physical_broadcast(void)
{
	unsigned ncpus = cpu_count();
	unsigned long cr3 = read_cr3();
	u32 broadcast_address = enable_x2apic() ? 0xffffffff : 0xff;

	handle_irq(BROADCAST_VECTOR, broadcast_handler);
	for (int c = 1; c < ncpus; c++)
		on_cpu(c, update_cr3, (void *)cr3);

	printf("starting broadcast (%s)\n", enable_x2apic() ? "x2apic" : "xapic");
	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_INT_ASSERT |
			BROADCAST_VECTOR, broadcast_address);
	report("APIC physical broadcast address", broadcast_received(ncpus));

	apic_icr_write(APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_INT_ASSERT |
			BROADCAST_VECTOR | APIC_DEST_ALLINC, 0);
	report("APIC physical broadcast shorthand", broadcast_received(ncpus));
}

static void wait_until_tmcct_common(uint32_t initial_count, bool stop_when_half, bool should_wrap_around)
{
	uint32_t tmcct = apic_read(APIC_TMCCT);

	if (tmcct) {
		while (tmcct > (initial_count / 2))
			tmcct = apic_read(APIC_TMCCT);

		if ( stop_when_half )
			return;

		/* Wait until the counter reach 0 or wrap-around */
		while ( tmcct <= (initial_count / 2) && tmcct > 0 )
			tmcct = apic_read(APIC_TMCCT);

		/* Wait specifically for wrap around to skip 0 TMCCR if we were asked to */
		while (should_wrap_around && !tmcct)
			tmcct = apic_read(APIC_TMCCT);
	}
}

static void wait_until_tmcct_is_zero(uint32_t initial_count, bool stop_when_half)
{
	return wait_until_tmcct_common(initial_count, stop_when_half, false);
}

static void wait_until_tmcct_wrap_around(uint32_t initial_count, bool stop_when_half)
{
	return wait_until_tmcct_common(initial_count, stop_when_half, true);
}

static inline void apic_change_mode(unsigned long new_mode)
{
	uint32_t lvtt;

	lvtt = apic_read(APIC_LVTT);
	apic_write(APIC_LVTT, (lvtt & ~APIC_LVT_TIMER_MASK) | new_mode);
}

static void test_apic_change_mode(void)
{
	uint32_t tmict = 0x999999;

	printf("starting apic change mode\n");

	apic_write(APIC_TMICT, tmict);

	apic_change_mode(APIC_LVT_TIMER_PERIODIC);

	report("TMICT value reset", apic_read(APIC_TMICT) == tmict);

	/* Testing one-shot */
	apic_change_mode(APIC_LVT_TIMER_ONESHOT);
	apic_write(APIC_TMICT, tmict);
	report("TMCCT should have a non-zero value", apic_read(APIC_TMCCT));

	wait_until_tmcct_is_zero(tmict, false);
	report("TMCCT should have reached 0", !apic_read(APIC_TMCCT));

	/*
	 * Write TMICT before changing mode from one-shot to periodic TMCCT should
	 * be reset to TMICT periodicly
	 */
	apic_write(APIC_TMICT, tmict);
	wait_until_tmcct_is_zero(tmict, true);
	apic_change_mode(APIC_LVT_TIMER_PERIODIC);
	report("TMCCT should have a non-zero value", apic_read(APIC_TMCCT));

	/*
	 * After the change of mode, the counter should not be reset and continue
	 * counting down from where it was
	 */
	report("TMCCT should not be reset to TMICT value", apic_read(APIC_TMCCT) < (tmict / 2));
	/*
	 * Specifically wait for timer wrap around and skip 0.
	 * Under KVM lapic there is a possibility that a small amount of consecutive
	 * TMCCR reads return 0 while hrtimer is reset in an async callback
	 */
	wait_until_tmcct_wrap_around(tmict, false);
	report("TMCCT should be reset to the initial-count", apic_read(APIC_TMCCT) > (tmict / 2));

	wait_until_tmcct_is_zero(tmict, true);
	/*
	 * Keep the same TMICT and change timer mode to one-shot
	 * TMCCT should be > 0 and count-down to 0
	 */
	apic_change_mode(APIC_LVT_TIMER_ONESHOT);
	report("TMCCT should not be reset to init", apic_read(APIC_TMCCT) < (tmict / 2));
	wait_until_tmcct_is_zero(tmict, false);
	report("TMCCT should have reach zero", !apic_read(APIC_TMCCT));

	/* now tmcct == 0 and tmict != 0 */
	apic_change_mode(APIC_LVT_TIMER_PERIODIC);
	report("TMCCT should stay at zero", !apic_read(APIC_TMCCT));
}

#define KVM_HC_SEND_IPI 10

static void test_pv_ipi(void)
{
    int ret;
    unsigned long a0 = 0xFFFFFFFF, a1 = 0, a2 = 0xFFFFFFFF, a3 = 0x0;

    asm volatile("vmcall" : "=a"(ret) :"a"(KVM_HC_SEND_IPI), "b"(a0), "c"(a1), "d"(a2), "S"(a3));
    report("PV IPIs testing", !ret);
}

int main(void)
{
    setup_vm();
    smp_init();

    test_lapic_existence();

    mask_pic_interrupts();
    test_apic_id();
    test_apic_disable();
    test_enable_x2apic();
    test_apicbase();

    test_self_ipi();
    test_physical_broadcast();
    test_pv_ipi();

    test_sti_nmi();
    test_multiple_nmi();

    test_apic_timer_one_shot();
    test_apic_change_mode();
    test_tsc_deadline_timer();

    return report_summary();
}
