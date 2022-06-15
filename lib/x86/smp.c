
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
#ifdef __i386__
extern u8 ap_rm_gdt_descr;
#endif

/* The BSP is online from time zero. */
atomic_t cpu_online_count = { .counter = 1 };

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
#endif
}

void ap_init(void)
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

	/* INIT */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT, 0);

	/* SIPI */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_STARTUP, 0);

	_cpu_count = fwcfg_get_nb_cpus();

	printf("smp: waiting for %d APs\n", _cpu_count - 1);
	while (_cpu_count != atomic_read(&cpu_online_count))
		cpu_relax();
}
