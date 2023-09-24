/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Simple cpumask implementation
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 */
#ifndef _CPUMASK_H_
#define _CPUMASK_H_
#include <asm/setup.h>
#include <bitops.h>

#define CPUMASK_NR_LONGS ((NR_CPUS + BITS_PER_LONG - 1) / BITS_PER_LONG)

typedef struct cpumask {
	unsigned long bits[CPUMASK_NR_LONGS];
} cpumask_t;

#define cpumask_bits(maskp) ((maskp)->bits)

static inline void cpumask_set_cpu(int cpu, cpumask_t *mask)
{
	assert(cpu >= 0 && cpu < nr_cpus);
	set_bit(cpu, cpumask_bits(mask));
}

static inline void cpumask_clear_cpu(int cpu, cpumask_t *mask)
{
	assert(cpu >= 0 && cpu < nr_cpus);
	clear_bit(cpu, cpumask_bits(mask));
}

static inline int cpumask_test_cpu(int cpu, const cpumask_t *mask)
{
	assert(cpu >= 0 && cpu < nr_cpus);
	return test_bit(cpu, cpumask_bits(mask));
}

static inline int cpumask_test_and_set_cpu(int cpu, cpumask_t *mask)
{
	assert(cpu >= 0 && cpu < nr_cpus);
	return test_and_set_bit(cpu, cpumask_bits(mask));
}

static inline int cpumask_test_and_clear_cpu(int cpu, cpumask_t *mask)
{
	assert(cpu >= 0 && cpu < nr_cpus);
	return test_and_clear_bit(cpu, cpumask_bits(mask));
}

static inline void cpumask_setall(cpumask_t *mask)
{
	int i;
	for (i = 0; i < nr_cpus; i += BITS_PER_LONG)
		cpumask_bits(mask)[BIT_WORD(i)] = ~0UL;
	i -= BITS_PER_LONG;
	if ((nr_cpus - i) < BITS_PER_LONG)
		cpumask_bits(mask)[BIT_WORD(i)] = BIT_MASK(nr_cpus - i) - 1;
}

static inline void cpumask_clear(cpumask_t *mask)
{
	int i;
	for (i = 0; i < nr_cpus; i += BITS_PER_LONG)
		cpumask_bits(mask)[BIT_WORD(i)] = 0UL;
}

static inline bool cpumask_empty(const cpumask_t *mask)
{
	int i;
	for (i = 0; i < nr_cpus; i += BITS_PER_LONG) {
		if (i < NR_CPUS) { /* silence crazy compiler warning */
			if (cpumask_bits(mask)[BIT_WORD(i)] != 0UL)
				return false;
		}
	}
	return true;
}

static inline bool cpumask_full(const cpumask_t *mask)
{
	int i;
	for (i = 0; i < nr_cpus; i += BITS_PER_LONG) {
		if (cpumask_bits(mask)[BIT_WORD(i)] != ~0UL) {
			if ((nr_cpus - i) >= BITS_PER_LONG)
				return false;
			if (cpumask_bits(mask)[BIT_WORD(i)]
					!= BIT_MASK(nr_cpus - i) - 1)
				return false;
		}
	}
	return true;
}

static inline int cpumask_weight(const cpumask_t *mask)
{
	int w = 0, i;

	for (i = 0; i < nr_cpus; ++i)
		if (cpumask_test_cpu(i, mask))
			++w;
	return w;
}

static inline void cpumask_copy(cpumask_t *dst, const cpumask_t *src)
{
	memcpy(cpumask_bits(dst), cpumask_bits(src),
			CPUMASK_NR_LONGS * sizeof(long));
}

static inline int cpumask_next(int cpu, const cpumask_t *mask)
{
	while (++cpu < nr_cpus && !cpumask_test_cpu(cpu, mask))
		;
	return cpu;
}

#define for_each_cpu(cpu, mask)					\
	for ((cpu) = cpumask_next(-1, mask);			\
			(cpu) < nr_cpus; 			\
			(cpu) = cpumask_next(cpu, mask))

extern cpumask_t cpu_present_mask;
extern cpumask_t cpu_online_mask;
extern cpumask_t cpu_idle_mask;
#define cpu_present(cpu)		cpumask_test_cpu(cpu, &cpu_present_mask)
#define cpu_online(cpu)			cpumask_test_cpu(cpu, &cpu_online_mask)
#define cpu_idle(cpu)			cpumask_test_cpu(cpu, &cpu_idle_mask)
#define for_each_present_cpu(cpu)	for_each_cpu(cpu, &cpu_present_mask)
#define for_each_online_cpu(cpu)	for_each_cpu(cpu, &cpu_online_mask)

static inline void set_cpu_present(int cpu, bool present)
{
	if (present)
		cpumask_set_cpu(cpu, &cpu_present_mask);
	else
		cpumask_clear_cpu(cpu, &cpu_present_mask);
}

static inline void set_cpu_online(int cpu, bool online)
{
	if (online)
		cpumask_set_cpu(cpu, &cpu_online_mask);
	else
		cpumask_clear_cpu(cpu, &cpu_online_mask);
}

static inline void set_cpu_idle(int cpu, bool idle)
{
	if (idle)
		cpumask_set_cpu(cpu, &cpu_idle_mask);
	else
		cpumask_clear_cpu(cpu, &cpu_idle_mask);
}

#endif /* _CPUMASK_H_ */
