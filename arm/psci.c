/*
 * PSCI tests
 *
 * Copyright (C) 2017, Red Hat, Inc.
 * Author: Levente Kurusa <lkurusa@redhat.com>
 * Author: Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <errata.h>
#include <libcflat.h>

#include <asm/delay.h>
#include <asm/mmu.h>
#include <asm/processor.h>
#include <asm/psci.h>
#include <asm/smp.h>

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
static cpumask_t cpu_on_ready, cpu_on_done, cpu_off_done;
static volatile int cpu_on_start;
static volatile int cpu_off_start;

extern void secondary_entry(void);
static void cpu_on_do_wake_target(void)
{
	int cpu = smp_processor_id();

	cpumask_set_cpu(cpu, &cpu_on_ready);
	while (!cpu_on_start)
		cpu_relax();
	cpu_on_ret[cpu] = psci_cpu_on(cpus[1], __pa(secondary_entry));
	cpumask_set_cpu(cpu, &cpu_on_done);
}

static void cpu_on_target(void)
{
	int cpu = smp_processor_id();

	cpumask_set_cpu(cpu, &cpu_on_done);
}

extern struct secondary_data secondary_data;

/* Open code the setup part from smp_boot_secondary(). */
static void psci_cpu_on_prepare_secondary(int cpu, secondary_entry_fn entry)
{
	secondary_data.stack = thread_stack_alloc();
	secondary_data.entry = entry;
	mmu_mark_disabled(cpu);
}

static bool psci_cpu_on_test(void)
{
	bool failed = false;
	int ret_success = 0;
	int i, cpu;

	for_each_present_cpu(cpu) {
		if (cpu < 2)
			continue;
		smp_boot_secondary(cpu, cpu_on_do_wake_target);
	}

	cpumask_set_cpu(0, &cpu_on_ready);
	cpumask_set_cpu(1, &cpu_on_ready);
	while (!cpumask_full(&cpu_on_ready))
		cpu_relax();

	/*
	 * Configure CPU 1 after all secondaries are online to avoid
	 * secondary_data being overwritten.
	 */
	psci_cpu_on_prepare_secondary(1, cpu_on_target);

	cpu_on_start = 1;
	smp_mb();

	cpu_on_ret[0] = psci_cpu_on(cpus[1], __pa(secondary_entry));
	cpumask_set_cpu(0, &cpu_on_done);

	report_info("waiting for CPU1 to come online...");
	for (i = 0; i < 100; i++) {
		mdelay(10);
		if (cpumask_full(&cpu_on_done))
			break;
	}

	if (!cpumask_full(&cpu_on_done)) {
		for_each_present_cpu(cpu) {
			if (!cpumask_test_cpu(cpu, &cpu_on_done)) {
				if (cpu == 1)
					report_info("CPU1 failed to come online");
				else
					report_info("CPU%d failed to online CPU1", cpu);
			}
		}
		failed = true;
	}

	for_each_cpu(cpu, &cpu_on_done) {
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

static void cpu_off_secondary_entry(void *data)
{
	int cpu = smp_processor_id();

	while (!cpu_off_start)
		cpu_relax();
	cpumask_set_cpu(cpu, &cpu_off_done);
	cpu_psci_cpu_die();
}

static bool psci_cpu_off_test(void)
{
	bool failed = false;
	int i, count, cpu;

	for_each_present_cpu(cpu) {
		if (cpu == 0)
			continue;
		on_cpu_async(cpu, cpu_off_secondary_entry, NULL);
	}

	cpumask_set_cpu(0, &cpu_off_done);

	cpu_off_start = 1;
	report_info("waiting for the CPUs to be offlined...");
	while (!cpumask_full(&cpu_off_done))
		cpu_relax();

	/* Allow all the other CPUs to complete the operation */
	for (i = 0; i < 100; i++) {
		mdelay(10);

		count = 0;
		for_each_present_cpu(cpu) {
			if (cpu == 0)
				continue;
			if (psci_affinity_info(cpus[cpu], 0) != PSCI_0_2_AFFINITY_LEVEL_OFF)
				count++;
		}
		if (count == 0)
			break;
	}

	/* Try to catch CPUs that return from CPU_OFF. */
	if (count == 0)
		mdelay(100);

	for_each_present_cpu(cpu) {
		if (cpu == 0)
			continue;
		if (cpu_idle(cpu)) {
			report_info("CPU%d failed to be offlined", cpu);
			if (psci_affinity_info(cpus[cpu], 0) == PSCI_0_2_AFFINITY_LEVEL_OFF)
				report_info("AFFINITY_INFO incorrectly reports CPU%d as offline", cpu);
			failed = true;
		}
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

	assert(!cpu_idle(0));

	if (!ERRATA(6c7a5dce22b3) || cpumask_weight(&cpu_idle_mask) == nr_cpus - 1)
		report(psci_cpu_off_test(), "cpu-off");
	else
		report_skip("Skipping cpu-off test because the cpu-on test failed");

done:
#if 0
	report_summary();
	psci_invoke(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
	report_fail("system-off");
	return 1; /* only reaches here if system-off fails */
#else
	return report_summary();
#endif
}
