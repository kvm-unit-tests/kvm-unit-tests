/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ON_CPUS_H_
#define _ON_CPUS_H_
#include <stdbool.h>
#include <cpumask.h>

extern bool cpu0_calls_idle;

void do_idle(void);

void on_cpu_async(int cpu, void (*func)(void *data), void *data);
void on_cpu(int cpu, void (*func)(void *data), void *data);
void on_cpus(void (*func)(void *data), void *data);
void on_cpumask_async(const cpumask_t *mask, void (*func)(void *data), void *data);
void on_cpumask(const cpumask_t *mask, void (*func)(void *data), void *data);

#endif /* _ON_CPUS_H_ */
