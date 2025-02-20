/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Simple cpumask implementation
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 */
#ifndef _CPUMASK_H_
#define _CPUMASK_H_
#include <bitops.h>
#include <limits.h>
#include <asm/setup.h>

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
	memset(mask, 0xff, sizeof(*mask));
}

static inline void cpumask_clear(cpumask_t *mask)
{
	memset(mask, 0, sizeof(*mask));
}

/* true if src1 is a subset of src2 */
static inline bool cpumask_subset(const struct cpumask *src1, const struct cpumask *src2)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;
	int i;

	for (i = 0; i < BIT_WORD(nr_cpus); ++i) {
		if (cpumask_bits(src1)[i] & ~cpumask_bits(src2)[i])
			return false;
	}

	return !lastmask || !((cpumask_bits(src1)[i] & ~cpumask_bits(src2)[i]) & lastmask);
}

/* false if dst is empty */
static inline bool cpumask_and(cpumask_t *dst, const cpumask_t *src1, const cpumask_t *src2)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;
	unsigned long ret = 0;
	int i;

	for (i = 0; i < BIT_WORD(nr_cpus); ++i) {
		cpumask_bits(dst)[i] = cpumask_bits(src1)[i] & cpumask_bits(src2)[i];
		ret |= cpumask_bits(dst)[i];
	}

	cpumask_bits(dst)[i] = (cpumask_bits(src1)[i] & cpumask_bits(src2)[i]) & lastmask;

	return ret | cpumask_bits(dst)[i];
}

static inline void cpumask_or(cpumask_t *dst, const cpumask_t *src1, const cpumask_t *src2)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;
	int i;

	for (i = 0; i < BIT_WORD(nr_cpus); ++i)
		cpumask_bits(dst)[i] = cpumask_bits(src1)[i] | cpumask_bits(src2)[i];

	cpumask_bits(dst)[i] = (cpumask_bits(src1)[i] | cpumask_bits(src2)[i]) & lastmask;
}

static inline void cpumask_xor(cpumask_t *dst, const cpumask_t *src1, const cpumask_t *src2)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;
	int i;

	for (i = 0; i < BIT_WORD(nr_cpus); ++i)
		cpumask_bits(dst)[i] = cpumask_bits(src1)[i] ^ cpumask_bits(src2)[i];

	cpumask_bits(dst)[i] = (cpumask_bits(src1)[i] ^ cpumask_bits(src2)[i]) & lastmask;
}

/* false if dst is empty */
static inline bool cpumask_andnot(cpumask_t *dst, const cpumask_t *src1, const cpumask_t *src2)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;
	unsigned long ret = 0;
	int i;

	for (i = 0; i < BIT_WORD(nr_cpus); ++i) {
		cpumask_bits(dst)[i] = cpumask_bits(src1)[i] & ~cpumask_bits(src2)[i];
		ret |= cpumask_bits(dst)[i];
	}

	cpumask_bits(dst)[i] = (cpumask_bits(src1)[i] & ~cpumask_bits(src2)[i]) & lastmask;

	return ret | cpumask_bits(dst)[i];
}

static inline bool cpumask_equal(const struct cpumask *src1, const struct cpumask *src2)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;
	int i;

	for (i = 0; i < BIT_WORD(nr_cpus); ++i) {
		if (cpumask_bits(src1)[i] != cpumask_bits(src2)[i])
			return false;
	}

	return !lastmask || (cpumask_bits(src1)[i] & lastmask) == (cpumask_bits(src2)[i] & lastmask);
}

static inline bool cpumask_empty(const cpumask_t *mask)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;

	for (int i = 0; i < BIT_WORD(nr_cpus); ++i)
		if (cpumask_bits(mask)[i])
			return false;

	return !lastmask || !(cpumask_bits(mask)[BIT_WORD(nr_cpus)] & lastmask);
}

static inline bool cpumask_full(const cpumask_t *mask)
{
	unsigned long lastmask = BIT_MASK(nr_cpus) - 1;

	for (int i = 0; i < BIT_WORD(nr_cpus); ++i)
		if (cpumask_bits(mask)[i] != ULONG_MAX)
			return false;

	return !lastmask || (cpumask_bits(mask)[BIT_WORD(nr_cpus)] & lastmask) == lastmask;
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
