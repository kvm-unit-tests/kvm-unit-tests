/*
 * PSCI tests
 *
 * Copyright (C) 2017, Red Hat, Inc.
 * Author: Levente Kurusa <lkurusa@redhat.com>
 * Author: Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <errata.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <asm/psci.h>

static bool invalid_function_exception;

#ifdef __arm__
static void invalid_function_handler(struct pt_regs *regs __unused)
{
	invalid_function_exception = true;
}
#else
static void invalid_function_handler(struct pt_regs *regs, unsigned int esr __unused)
{
	invalid_function_exception = true;
	regs->pc += 4;
}
#endif

static void install_invalid_function_handler(exception_fn handler)
{
#ifdef __arm__
	install_exception_handler(EXCPTN_UND, handler);
#else
	install_exception_handler(EL1H_SYNC, ESR_EL1_EC_UNKNOWN, handler);
#endif
}

static bool psci_invalid_function(void)
{
	bool pass;

	install_invalid_function_handler(invalid_function_handler);

	pass = psci_invoke(1337, 0, 0, 0) == PSCI_RET_NOT_SUPPORTED || invalid_function_exception;

	install_invalid_function_handler(NULL);
	return pass;
}

static int psci_affinity_info(unsigned long target_affinity, uint32_t lowest_affinity_level)
{
#ifdef __arm__
	return psci_invoke(PSCI_0_2_FN_AFFINITY_INFO, target_affinity, lowest_affinity_level, 0);
#else
	return psci_invoke(PSCI_0_2_FN64_AFFINITY_INFO, target_affinity, lowest_affinity_level, 0);
#endif
}

static bool psci_affinity_info_on(void)
{
	return psci_affinity_info(cpus[0], 0) == PSCI_0_2_AFFINITY_LEVEL_ON;
}

static bool psci_affinity_info_off(void)
{
	return psci_affinity_info(cpus[1], 0) == PSCI_0_2_AFFINITY_LEVEL_OFF;
}

static int cpu_on_ret[NR_CPUS];
static cpumask_t cpu_on_ready, cpu_on_done;
static volatile int cpu_on_start;

static void cpu_on_secondary_entry(void)
{
	int cpu = smp_processor_id();

	cpumask_set_cpu(cpu, &cpu_on_ready);
	while (!cpu_on_start)
		cpu_relax();
	cpu_on_ret[cpu] = psci_cpu_on(cpus[1], __pa(halt));
	cpumask_set_cpu(cpu, &cpu_on_done);
}

static bool psci_cpu_on_test(void)
{
	bool failed = false;
	int ret_success = 0;
	int cpu;

	cpumask_set_cpu(1, &cpu_on_ready);
	cpumask_set_cpu(1, &cpu_on_done);

	for_each_present_cpu(cpu) {
		if (cpu < 2)
			continue;
		smp_boot_secondary(cpu, cpu_on_secondary_entry);
	}

	cpumask_set_cpu(0, &cpu_on_ready);
	while (!cpumask_full(&cpu_on_ready))
		cpu_relax();

	cpu_on_start = 1;
	smp_mb();

	cpu_on_ret[0] = psci_cpu_on(cpus[1], __pa(halt));
	cpumask_set_cpu(0, &cpu_on_done);

	while (!cpumask_full(&cpu_on_done))
		cpu_relax();

	for_each_present_cpu(cpu) {
		if (cpu == 1)
			continue;
		if (cpu_on_ret[cpu] == PSCI_RET_SUCCESS) {
			ret_success++;
		} else if (cpu_on_ret[cpu] != PSCI_RET_ALREADY_ON) {
			report_info("unexpected cpu_on return value: caller=CPU%d, ret=%d", cpu, cpu_on_ret[cpu]);
			failed = true;
		}
	}

	if (ret_success != 1) {
		report_info("got %d CPU_ON success", ret_success);
		failed = true;
	}

	return !failed;
}

int main(void)
{
	int ver = psci_invoke(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);

	report_prefix_push("psci");

	if (nr_cpus < 2) {
		report_skip("At least 2 cpus required");
		goto done;
	}

	report_info("PSCI version %d.%d", PSCI_VERSION_MAJOR(ver),
					  PSCI_VERSION_MINOR(ver));
	report(psci_invalid_function(), "invalid-function");
	report(psci_affinity_info_on(), "affinity-info-on");
	report(psci_affinity_info_off(), "affinity-info-off");

	if (ERRATA(6c7a5dce22b3))
		report(psci_cpu_on_test(), "cpu-on");
	else
		report_skip("Skipping unsafe cpu-on test. Set ERRATA_6c7a5dce22b3=y to enable.");

done:
#if 0
	report_summary();
	psci_invoke(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
	report(false, "system-off");
	return 1; /* only reaches here if system-off fails */
#else
	return report_summary();
#endif
}
