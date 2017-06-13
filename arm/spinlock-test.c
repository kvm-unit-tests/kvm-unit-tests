/*
 * Spinlock test
 *
 * This code is based on code from the tcg_baremetal_tests.
 *
 * Copyright (C) 2015 Virtual Open Systems SAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <libcflat.h>
#include <asm/smp.h>
#include <asm/barrier.h>

#define LOOP_SIZE 10000000

struct lock_ops {
	void (*lock)(int *v);
	void (*unlock)(int *v);
};
static struct lock_ops lock_ops;

static void gcc_builtin_lock(int *lock_var)
{
	while (__sync_lock_test_and_set(lock_var, 1));
}
static void gcc_builtin_unlock(int *lock_var)
{
	__sync_lock_release(lock_var);
}
static void none_lock(int *lock_var)
{
	while (*(volatile int *)lock_var != 0);
	*(volatile int *)lock_var = 1;
}
static void none_unlock(int *lock_var)
{
	*(volatile int *)lock_var = 0;
}

static int global_a, global_b;
static int global_lock;

static void test_spinlock(void *data __unused)
{
	int i, errors = 0;
	int cpu = smp_processor_id();

	printf("CPU%d online\n", cpu);

	for (i = 0; i < LOOP_SIZE; i++) {

		lock_ops.lock(&global_lock);

		if (global_a == (cpu + 1) % 2) {
			global_a = 1;
			global_b = 0;
		} else {
			global_a = 0;
			global_b = 1;
		}

		if (global_a == global_b)
			errors++;

		lock_ops.unlock(&global_lock);
	}
	report("CPU%d: Done - Errors: %d", errors == 0, cpu, errors);
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "bad") != 0) {
		lock_ops.lock = gcc_builtin_lock;
		lock_ops.unlock = gcc_builtin_unlock;
	} else {
		lock_ops.lock = none_lock;
		lock_ops.unlock = none_unlock;
	}

	on_cpus(test_spinlock, NULL);

	return report_summary();
}
