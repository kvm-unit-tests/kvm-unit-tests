
#include <libcflat.h>

#include <asm/barrier.h>

#include "processor.h"
#include "atomic.h"
#include "smp.h"
#include "apic.h"
#include "fwcfg.h"
#include "desc.h"
#include "alloc_page.h"
#include "asm/page.h"

#define IPI_VECTOR 0x20

typedef void (*ipi_function_type)(void *data);

static struct spinlock ipi_lock;
static volatile ipi_function_type ipi_function;
static void *volatile ipi_data;
static volatile int ipi_done;
static volatile bool ipi_wait;
static int _cpu_count;
static atomic_t active_cpus;
extern u8 rm_trampoline, rm_trampoline_end;
#if defined(__i386__) || defined(CONFIG_EFI)
extern u8 ap_rm_gdt_descr;
#endif

#ifdef CONFIG_EFI
extern u8 ap_rm_gdt, ap_rm_gdt_end;
extern u8 ap_start32;
extern u32 smp_stacktop;
extern u8 stacktop;
#endif

/* The BSP is online from time zero. */
atomic_t cpu_online_count = { .counter = 1 };
unsigned char online_cpus[(MAX_TEST_CPUS + 7) / 8];

static __attribute__((used)) void ipi(void)
{
	void (*function)(void *data) = ipi_function;
	void *data = ipi_data;
	bool wait = ipi_wait;

	if (!wait) {
		ipi_done = 1;
		apic_write(APIC_EOI, 0);
	}
	function(data);
	atomic_dec(&active_cpus);
	if (wait) {
		ipi_done = 1;
		apic_write(APIC_EOI, 0);
	}
}

asm (
	 "ipi_entry: \n"
	 "   call ipi \n"
#ifndef __x86_64__
	 "   iret"
#else
	 "   iretq"
#endif
	 );

int cpu_count(void)
{
	return _cpu_count;
}

int smp_id(void)
{
	return this_cpu_read_smp_id();
}

static void setup_smp_id(void *data)
{
	this_cpu_write_smp_id(apic_id());
}

static void __on_cpu(int cpu, void (*function)(void *data), void *data, int wait)
{
	const u32 ipi_icr = APIC_INT_ASSERT | APIC_DEST_PHYSICAL | APIC_DM_FIXED | IPI_VECTOR;
	unsigned int target = id_map[cpu];

	spin_lock(&ipi_lock);
	if (target == smp_id()) {
		function(data);
	} else {
		atomic_inc(&active_cpus);
		ipi_done = 0;
		ipi_function = function;
		ipi_data = data;
		ipi_wait = wait;
		apic_icr_write(ipi_icr, target);
		while (!ipi_done)
			;
	}
	spin_unlock(&ipi_lock);
}

void on_cpu(int cpu, void (*function)(void *data), void *data)
{
	__on_cpu(cpu, function, data, 1);
}

void on_cpu_async(int cpu, void (*function)(void *data), void *data)
{
	__on_cpu(cpu, function, data, 0);
}

void on_cpus(void (*function)(void *data), void *data)
{
	int cpu;

	for (cpu = cpu_count() - 1; cpu >= 0; --cpu)
		on_cpu_async(cpu, function, data);

	while (cpus_active() > 1)
		pause();
}

int cpus_active(void)
{
	return atomic_read(&active_cpus);
}

void smp_init(void)
{
	int i;
	void ipi_entry(void);

	setup_idt();
	init_apic_map();
	set_idt_entry(IPI_VECTOR, ipi_entry, 0);

	setup_smp_id(0);
	for (i = 1; i < cpu_count(); ++i)
		on_cpu(i, setup_smp_id, 0);

	atomic_inc(&active_cpus);
}

static void do_reset_apic(void *data)
{
	reset_apic();
}

void smp_reset_apic(void)
{
	int i;

	reset_apic();
	for (i = 1; i < cpu_count(); ++i)
		on_cpu(i, do_reset_apic, 0);

	atomic_inc(&active_cpus);
}

static void setup_rm_gdt(void)
{
#ifdef __i386__
	struct descriptor_table_ptr *rm_gdt =
		(struct descriptor_table_ptr *) (&ap_rm_gdt_descr - &rm_trampoline);
	/*
	 * On i386, place the gdt descriptor to be loaded from SIPI vector right after
	 * the vector code.
	 */
	sgdt(rm_gdt);
#elif defined(CONFIG_EFI)
	idt_entry_t *gate_descr;

	/*
	 * The realmode trampoline on EFI has the following layout:
	 *
	 * |rm_trampoline:
	 * |sipi_entry:
	 * |  <AP bootstrapping code called from SIPI>
	 * |ap_rm_gdt:
	 * |  <GDT used for 16-bit -> 32-bit trasition>
	 * |ap_rm_gdt_descr:
	 * |  <GDT descriptor for ap_rm_gdt>
	 * |sipi_end:
	 * |  <End of trampoline>
	 * |rm_trampoline_end:
	 *
	 * After relocating to the lowmem address pointed to by realmode_trampoline,
	 * the realmode GDT descriptor needs to contain the relocated address of
	 * ap_rm_gdt.
	 */
	volatile struct descriptor_table_ptr *rm_gdt_descr =
			(struct descriptor_table_ptr *) (&ap_rm_gdt_descr - &rm_trampoline);
	rm_gdt_descr->base = (ulong) ((u32) (&ap_rm_gdt - &rm_trampoline));
	rm_gdt_descr->limit = (u16) (&ap_rm_gdt_end - &ap_rm_gdt - 1);

	/*
	 * Since 1. compile time calculation of offsets is not allowed when
	 * building with -shared, and 2. rip-relative addressing is not supported in
	 * 16-bit mode, the relocated address of ap_rm_gdt_descr needs to be stored at
	 * a location known to / accessible from the trampoline.
	 *
	 * Use the last two bytes of the trampoline page (REALMODE_GDT_LOWMEM) to store
	 * a pointer to relocated ap_rm_gdt_descr addr. This way, the trampoline code can
	 * find the relocated descriptor using the lowmem address at pa=REALMODE_GDT_LOWMEM,
	 * and this relocated descriptor points to the relocated GDT.
	 */
	*((u16 *)(REALMODE_GDT_LOWMEM)) = (u16) (u64) rm_gdt_descr;

	/*
	 * Set up a call gate to the 32-bit entrypoint (ap_start32) within GDT, since
	 * EFI may not load the 32-bit AP entrypoint (ap_start32) low enough
	 * to be reachable from the SIPI vector.
	 *
	 * Since kvm-unit-tests builds with -shared, this location needs to be fetched
	 * at runtime, and rip-relative addressing is not supported in 16-bit mode. This
	 * prevents using a long jump to ap_start32 (`ljmpl $cs, $ap_start32`).
	 *
	 * As an alternative, a far return via `push $cs; push $label; lret` would require
	 * an intermediate trampoline since $label must still be within 0 - 0xFFFF for
	 * 16-bit far return to work.
	 *
	 * Using a call gate allows for an easier 16-bit -> 32-bit transition via `lcall`.
	 *
	 * GDT layout:
	 *
	 * Entry | Segment
	 * 0	 | NULL descr
	 * 1	 | Code segment descr
	 * 2	 | Data segment descr
	 * 3	 | Call gate descr
	 *
	 * This layout is only used for reaching 32-bit mode. APs load a 64-bit GDT
	 * later during boot, which does not need to follow this layout.
	 */
	gate_descr = ((void *)(&ap_rm_gdt - &rm_trampoline) + 3 * sizeof(gdt_entry_t));
	set_desc_entry(gate_descr, sizeof(gdt_entry_t), (void *) &ap_start32,
		       0x8 /* sel */, 0xc /* type */, 0 /* dpl */);
#endif
}

void bringup_aps(void)
{
	void *rm_trampoline_dst = RM_TRAMPOLINE_ADDR;
	size_t rm_trampoline_size = (&rm_trampoline_end - &rm_trampoline) + 1;
	assert(rm_trampoline_size < PAGE_SIZE);

	asm volatile("cld");

	/*
	 * Fill the trampoline page with with INT3 (0xcc) so that any AP
	 * that goes astray within the first page gets a fault.
	 */
	memset(rm_trampoline_dst, 0xcc /* INT3 */, PAGE_SIZE);

	memcpy(rm_trampoline_dst, &rm_trampoline, rm_trampoline_size);

	setup_rm_gdt();

#ifdef CONFIG_EFI
	smp_stacktop = ((u64) (&stacktop)) - PAGE_SIZE;
#endif

	/* INIT */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT, 0);

	/* SIPI */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_STARTUP, 0);

	_cpu_count = fwcfg_get_nb_cpus();

	printf("smp: waiting for %d APs\n", _cpu_count - 1);
	while (_cpu_count != atomic_read(&cpu_online_count))
		cpu_relax();
}
