// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test some powerpc instructions
 *
 * Copyright 2024 Nicholas Piggin, IBM Corp.
 */
#include <stdint.h>
#include <libcflat.h>
#include <migrate.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/atomic.h>
#include <asm/setup.h>
#include <asm/barrier.h>
#include <asm/smp.h>

static bool do_migrate;
static bool do_record;

#define RSV_SIZE 128

static uint8_t granule[RSV_SIZE] __attribute((__aligned__(RSV_SIZE)));

static void spin_lock(unsigned int *lock)
{
	unsigned int old;

	asm volatile ("1:"
		      "lwarx	%0,0,%2;"
		      "cmpwi	%0,0;"
		      "bne	1b;"
		      "stwcx.	%1,0,%2;"
		      "bne-	1b;"
		      "lwsync;"
		      : "=&r"(old) : "r"(1), "r"(lock) : "cr0", "memory");
}

static void spin_unlock(unsigned int *lock)
{
	asm volatile("lwsync;"
		     "stw	%1,%0;"
		     : "+m"(*lock) : "r"(0) : "memory");
}

static volatile bool got_interrupt;
static volatile struct pt_regs recorded_regs;

static void interrupt_handler(struct pt_regs *regs, void *opaque)
{
	assert(!got_interrupt);
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs_advance_insn(regs);
}

static void test_lwarx_stwcx(int argc, char *argv[])
{
	unsigned int *var = (unsigned int *)granule;
	unsigned int old;
	unsigned int result;

	*var = 0;
	asm volatile ("1:"
		      "lwarx	%0,0,%2;"
		      "stwcx.	%1,0,%2;"
		      "bne-	1b;"
		      : "=&r"(old) : "r"(1), "r"(var) : "cr0", "memory");
	report(old == 0 && *var == 1, "simple update");

	*var = 0;
	asm volatile ("li	%0,0;"
		      "stwcx.	%1,0,%2;"
		      "stwcx.	%1,0,%2;"
		      "bne-	1f;"
		      "li	%0,1;"
		      "1:"
		      : "=&r"(result)
		      : "r"(1), "r"(var) : "cr0", "memory");
	report(result == 0 && *var == 0, "failed stwcx. (no reservation)");

	*var = 0;
	asm volatile ("li	%0,0;"
		      "lwarx	%1,0,%4;"
		      "stw	%3,0(%4);"
		      "stwcx.	%2,0,%4;"
		      "bne-	1f;"
		      "li	%0,1;"
		      "1:"
		      : "=&r"(result), "=&r"(old)
		      : "r"(1), "r"(2), "r"(var) : "cr0", "memory");
	/* This is implementation specific, so don't fail */
	if (result == 0 && *var == 2)
		report(true, "failed stwcx. (intervening store)");
	else
		report(true, "succeeded stwcx. (intervening store)");

	handle_exception(0x600, interrupt_handler, NULL);
	handle_exception(0x700, interrupt_handler, NULL);

	/* Implementations may not necessarily invoke the alignment interrupt */
	old = 10;
	*var = 0;
	asm volatile (
		      "lwarx	%0,0,%1;"
		      : "+&r"(old) : "r"((char *)var + 1));
	report(old == 10 && got_interrupt && recorded_regs.trap == 0x600,
	       "unaligned lwarx causes fault");
	got_interrupt = false;

	/*
	 * Unaligned stwcx. is more difficult to test, at least under QEMU,
	 * the store does not proceed if there is no matching reservation, so
	 * the alignment handler does not get invoked. This is okay according
	 * to the Power ISA (unalignment does not necessarily invoke the
	 * alignment interrupt). But POWER CPUs do cause alignment interrupt.
	 */
	*var = 0;
	asm volatile (
		      "lwarx	%0,0,%2;"
		      "stwcx.	%1,0,%3;"
		      : "=&r"(old) : "r"(1), "r"(var), "r"((char *)var+1)
		      : "cr0", "memory");
	/*
	 * An unaligned larx/stcx. is not required by the ISA to cause an
	 * exception, and in TCG the stcx does not though it does on POWER CPUs.
	 */
	report_kfail(host_is_tcg, old == 0 && *var == 0 &&
				  got_interrupt && recorded_regs.trap == 0x600,
		     "unaligned stwcx. causes fault");
	got_interrupt = false;

	handle_exception(0x600, NULL, NULL);

}

static void test_lqarx_stqcx(int argc, char *argv[])
{
	union {
		__int128_t var;
		struct {
#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			unsigned long var1;
			unsigned long var2;
#else
			unsigned long var2;
			unsigned long var1;
#endif
		};
	} var __attribute__((aligned(16)));
	register unsigned long new1 asm("r8");
	register unsigned long new2 asm("r9");
	register unsigned long old1 asm("r10");
	register unsigned long old2 asm("r11");
	unsigned int result;

	var.var1 = 1;
	var.var2 = 2;

	(void)new2;
	(void)old2;

	old1 = 0;
	old2 = 0;
	new1 = 3;
	new2 = 4;
	asm volatile ("1:"
		      "lqarx	%0,0,%4;"
		      "stqcx.	%2,0,%4;"
		      "bne-	1b;"
		      : "=&r"(old1), "=&r"(old2)
		      : "r"(new1), "r"(new2), "r"(&var)
		      : "cr0", "memory");

	report(old1 == 2 && old2 == 1 && var.var1 == 4 && var.var2 == 3,
	       "simple update");

	var.var1 = 1;
	var.var2 = 2;
	new1 = 3;
	new2 = 4;
	asm volatile ("li	%0,0;"
		      "stqcx.	%1,0,%3;"
		      "stqcx.	%1,0,%3;"
		      "bne-	1f;"
		      "li	%0,1;"
		      "1:"
		      : "=&r"(result)
		      : "r"(new1), "r"(new2), "r"(&var)
		      : "cr0", "memory");
	report(result == 0 && var.var1 == 1 && var.var2 == 2,
	       "failed stqcx. (no reservation)");

	var.var1 = 1;
	var.var2 = 2;
	new1 = 3;
	new2 = 4;
	asm volatile ("li	%0,0;"
		      "lqarx	%1,0,%6;"
		      "std	%5,0(%6);"
		      "stqcx.	%3,0,%6;"
		      "bne-	1f;"
		      "li	%0,1;"
		      "1:"
		      : "=&r"(result), "=&r"(old1), "=&r"(old2)
		      : "r"(new1), "r"(new2), "r"(0), "r"(&var)
		      : "cr0", "memory");
	/* This is implementation specific, so don't fail */
	if (result == 0 && (var.var1 == 0 || var.var2 == 0))
		report(true, "failed stqcx. (intervening store)");
	else
		report(true, "succeeded stqcx. (intervening store)");
}

static void test_migrate_reserve(int argc, char *argv[])
{
	unsigned int *var = (unsigned int *)granule;
	unsigned int old;
	int i;
	int succeed = 0;

	if (!do_migrate)
		return;

	for (i = 0; i < 10; i++) {
		*var = 0x12345;
		asm volatile ("lwarx	%0,0,%1" : "=&r"(old) : "r"(var) : "memory");
		migrate_quiet();
		asm volatile ("stwcx.	%0,0,%1" : : "r"(0xf00d), "r"(var) : "cr0", "memory");
		if (*var == 0xf00d)
			succeed++;
	}

	if (do_record) {
		/*
		 * Running under TCG record-replay, reservations must not
		 * be lost by migration
		 */
		report(succeed > 0, "migrated reservation is not lost");
	} else {
		report(succeed == 0, "migrated reservation is lost");
	}

	report_prefix_pop();
}

#define ITERS 10000000
static int test_counter = 0;
static void test_inc_perf(int argc, char *argv[])
{
	int i;
	uint64_t tb1, tb2;

	tb1 = get_tb();
	for (i = 0; i < ITERS; i++)
		__atomic_fetch_add(&test_counter, 1, __ATOMIC_RELAXED);
	tb2 = get_tb();
	report(true, "atomic add takes %ldns",
		    (tb2 - tb1) * 1000000000 / ITERS / tb_hz);

	tb1 = get_tb();
	for (i = 0; i < ITERS; i++)
		__atomic_fetch_add(&test_counter, 1, __ATOMIC_SEQ_CST);
	tb2 = get_tb();
	report(true, "sequentially conssistent atomic add takes %ldns",
	       (tb2 - tb1) * 1000000000 / ITERS / tb_hz);
}

static long smp_inc_counter = 0;
static int smp_inc_started;

static void smp_inc_fn(int cpu_id)
{
	long i;

	atomic_fetch_inc(&smp_inc_started);
	while (smp_inc_started < nr_cpus_present)
		cpu_relax();

	for (i = 0; i < ITERS; i++)
		atomic_fetch_inc(&smp_inc_counter);
	atomic_fetch_dec(&smp_inc_started);
}

static void test_smp_inc(int argc, char **argv)
{
	if (nr_cpus_present < 2)
		return;

	if (!start_all_cpus(smp_inc_fn))
		report_abort("Failed to start secondary cpus");

	while (smp_inc_started < nr_cpus_present - 1)
		cpu_relax();
	smp_inc_fn(smp_processor_id());
	while (smp_inc_started > 0)
		cpu_relax();

	stop_all_cpus();

	report(smp_inc_counter == nr_cpus_present * ITERS,
	       "counter lost no increments");
}

static long smp_lock_counter __attribute__((aligned(128))) = 0;
static unsigned int smp_lock __attribute__((aligned(128)));
static int smp_lock_started;

static void smp_lock_fn(int cpu_id)
{
	long i;

	atomic_fetch_inc(&smp_lock_started);
	while (smp_lock_started < nr_cpus_present)
		cpu_relax();

	for (i = 0; i < ITERS; i++) {
		spin_lock(&smp_lock);
		smp_lock_counter++;
		spin_unlock(&smp_lock);
	}
	atomic_fetch_dec(&smp_lock_started);
}

static void test_smp_lock(int argc, char **argv)
{
	if (nr_cpus_present < 2)
		return;

	if (!start_all_cpus(smp_lock_fn))
		report_abort("Failed to start secondary cpus");

	while (smp_lock_started < nr_cpus_present - 1)
		cpu_relax();
	smp_lock_fn(smp_processor_id());
	while (smp_lock_started > 0)
		cpu_relax();

	stop_all_cpus();

	report(smp_lock_counter == nr_cpus_present * ITERS,
	       "counter lost no increments");
}

struct {
	const char *name;
	void (*func)(int argc, char **argv);
} hctests[] = {
	{ "lwarx/stwcx", test_lwarx_stwcx },
	{ "lqarx/stqcx", test_lqarx_stqcx },
	{ "migration", test_migrate_reserve },
	{ "performance", test_inc_perf },
	{ "SMP-atomic", test_smp_inc },
	{ "SMP-lock", test_smp_lock },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	int i;
	int all;

	all = argc == 1 || !strcmp(argv[1], "all");

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0) {
			do_record = true;
		}
		if (strcmp(argv[i], "-m") == 0) {
			do_migrate = true;
		}
	}

	report_prefix_push("atomics");

	for (i = 0; hctests[i].name != NULL; i++) {
		if (all || strcmp(argv[1], hctests[i].name) == 0) {
			report_prefix_push(hctests[i].name);
			hctests[i].func(argc, argv);
			report_prefix_pop();
		}
	}

	report_prefix_pop();

	return report_summary();
}
