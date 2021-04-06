/*
 * PSCI API
 * From arch/arm[64]/kernel/psci.c
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <devicetree.h>
#include <asm/psci.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/smp.h>

static int psci_invoke_none(unsigned int function_id, unsigned long arg0,
			    unsigned long arg1, unsigned long arg2)
{
	printf("No PSCI method configured! Can't invoke...\n");
	return PSCI_RET_NOT_PRESENT;
}

psci_invoke_fn psci_invoke = psci_invoke_none;

int psci_cpu_on(unsigned long cpuid, unsigned long entry_point)
{
#ifdef __arm__
	return psci_invoke(PSCI_0_2_FN_CPU_ON, cpuid, entry_point, 0);
#else
	return psci_invoke(PSCI_0_2_FN64_CPU_ON, cpuid, entry_point, 0);
#endif
}

extern void secondary_entry(void);
int cpu_psci_cpu_boot(unsigned int cpu)
{
	int err = psci_cpu_on(cpus[cpu], __pa(secondary_entry));
	if (err)
		printf("failed to boot CPU%d (%d)\n", cpu, err);
	return err;
}

void cpu_psci_cpu_die(void)
{
	int err = psci_invoke(PSCI_0_2_FN_CPU_OFF, 0, 0, 0);
	printf("CPU%d unable to power off (error = %d)\n", smp_processor_id(), err);
}

void psci_system_reset(void)
{
	psci_invoke(PSCI_0_2_FN_SYSTEM_RESET, 0, 0, 0);
}

void psci_system_off(void)
{
	int err = psci_invoke(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
	printf("CPU%d unable to do system off (error = %d)\n", smp_processor_id(), err);
}

void psci_set_conduit(void)
{
	const void *fdt = dt_fdt();
	const struct fdt_property *method;
	int node, len;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,psci-0.2");
	assert_msg(node >= 0, "PSCI v0.2 compatibility required");

	method = fdt_get_property(fdt, node, "method", &len);
	assert(method != NULL && len == 4);

	if (strcmp(method->data, "hvc") == 0)
		psci_invoke = psci_invoke_hvc;
	else if (strcmp(method->data, "smc") == 0)
		psci_invoke = psci_invoke_smc;
	else
		assert_msg(false, "Unknown PSCI conduit: %s", method->data);
}
