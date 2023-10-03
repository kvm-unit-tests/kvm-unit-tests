#ifndef _ASMARM_SMP_H_
#define _ASMARM_SMP_H_
/*
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <cpumask.h>
#include <asm/barrier.h>
#include <asm/thread_info.h>

#define smp_processor_id()		(current_thread_info()->cpu)

typedef void (*secondary_entry_fn)(void);

struct secondary_data {
	void *stack;            /* must be first member of struct */
	secondary_entry_fn entry;
};
extern struct secondary_data secondary_data;

#define smp_wait_for_event()	wfe()
#define smp_send_event()	sev()

extern bool cpu0_calls_idle;

extern void halt(void);
extern void do_idle(void);

extern void smp_boot_secondary(int cpu, secondary_entry_fn entry);
extern void on_cpu_async(int cpu, void (*func)(void *data), void *data);
extern void on_cpu(int cpu, void (*func)(void *data), void *data);
extern void on_cpus(void (*func)(void *data), void *data);

#endif /* _ASMARM_SMP_H_ */
