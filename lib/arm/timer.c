/*
 * Initialize timers.
 *
 * Copyright (C) 2022, Arm Ltd., Nikos Nikoleris <nikos.nikoleris@arm.com>
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <acpi.h>
#include <devicetree.h>
#include <libfdt/libfdt.h>
#include <asm/gic.h>
#include <asm/timer.h>

struct timer_state __timer_state;

static void timer_save_state_fdt(void)
{
	const struct fdt_property *prop;
	const void *fdt = dt_fdt();
	int node, len;
	u32 *data;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,armv8-timer");
	assert(node >= 0 || node == -FDT_ERR_NOTFOUND);

	if (node == -FDT_ERR_NOTFOUND) {
		__timer_state.ptimer.irq = -1;
		__timer_state.vtimer.irq = -1;
		return;
	}

	/*
	 * From Linux devicetree timer binding documentation
	 *
	 * interrupts <type irq flags>:
	 *      secure timer irq
	 *      non-secure timer irq            (ptimer)
	 *      virtual timer irq               (vtimer)
	 *      hypervisor timer irq
	 */
	prop = fdt_get_property(fdt, node, "interrupts", &len);
	assert(prop && len == (4 * 3 * sizeof(u32)));

	data = (u32 *) prop->data;
	assert(fdt32_to_cpu(data[3]) == 1 /* PPI */ );
	__timer_state.ptimer.irq = PPI(fdt32_to_cpu(data[4]));
	__timer_state.ptimer.irq_flags = fdt32_to_cpu(data[5]);
	assert(fdt32_to_cpu(data[6]) == 1 /* PPI */ );
	__timer_state.vtimer.irq = PPI(fdt32_to_cpu(data[7]));
	__timer_state.vtimer.irq_flags = fdt32_to_cpu(data[8]);
}

#ifdef CONFIG_EFI

#include <acpi.h>

static void timer_save_state_acpi(void)
{
	struct acpi_table_gtdt *gtdt = find_acpi_table_addr(GTDT_SIGNATURE);

	if (!gtdt) {
		printf("Cannot find ACPI GTDT");
		__timer_state.ptimer.irq = -1;
		__timer_state.vtimer.irq = -1;
		return;
	}

	__timer_state.ptimer.irq = gtdt->non_secure_el1_interrupt;
	__timer_state.ptimer.irq_flags = gtdt->non_secure_el1_flags;

	__timer_state.vtimer.irq = gtdt->virtual_timer_interrupt;
	__timer_state.vtimer.irq_flags = gtdt->virtual_timer_flags;
}

#else

static void timer_save_state_acpi(void)
{
	assert_msg(false, "ACPI not available");
}

#endif

void timer_save_state(void)
{
	if (dt_available())
		timer_save_state_fdt();
	else
		timer_save_state_acpi();
}
