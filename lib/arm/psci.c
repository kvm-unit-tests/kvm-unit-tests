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
			    unsigned long arg1, unsigned long arg2,
			    unsigned long arg3, unsigned long arg4,
			    unsigned long arg5, unsigned long arg6,
			    unsigned long arg7, unsigned long arg8,
			    unsigned long arg9, unsigned long arg10,
			    struct smccc_result *result)
{
	printf("No PSCI method configured! Can't invoke...\n");
	return PSCI_RET_NOT_PRESENT;
}

smccc_invoke_fn psci_invoke_fn = psci_invoke_none;

int psci_invoke(unsigned int function_id, unsigned long arg0,
		unsigned long arg1, unsigned long arg2)
{
	return psci_invoke_fn(function_id, arg0, arg1, arg2, 0, 0, 0, 0, 0, 0, 0, 0, NULL);
}

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

static void psci_set_conduit_fdt(void)
{
	const void *fdt = dt_fdt();
	const struct fdt_property *method;
	int node, len;

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,psci-0.2");
	assert_msg(node >= 0, "PSCI v0.2 compatibility required");

	method = fdt_get_property(fdt, node, "method", &len);
	assert(method != NULL && len == 4);

	if (strcmp(method->data, "hvc") == 0)
		psci_invoke_fn = arm_smccc_hvc;
	else if (strcmp(method->data, "smc") == 0)
		psci_invoke_fn = arm_smccc_smc;
	else
		assert_msg(false, "Unknown PSCI conduit: %s", method->data);
}

#ifdef CONFIG_EFI

#include <acpi.h>

static void psci_set_conduit_acpi(void)
{
	struct acpi_table_fadt *fadt = find_acpi_table_addr(FACP_SIGNATURE);

	assert_msg(fadt, "Unable to find ACPI FADT");
	assert_msg(fadt->arm_boot_flags & ACPI_FADT_PSCI_COMPLIANT,
		   "PSCI is not supported in this platform");

	if (fadt->arm_boot_flags & ACPI_FADT_PSCI_USE_HVC)
		psci_invoke_fn = arm_smccc_hvc;
	else
		psci_invoke_fn = arm_smccc_smc;
}

#else

static void psci_set_conduit_acpi(void)
{
	assert_msg(false, "ACPI not available");
}

#endif

void psci_set_conduit(void)
{
	if (dt_available())
		psci_set_conduit_fdt();
	else
		psci_set_conduit_acpi();
}
