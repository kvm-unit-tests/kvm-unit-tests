#ifndef _X86_SMP_H_
#define _X86_SMP_H_
#include <asm/spinlock.h>

void smp_init(void);

int cpu_count(void);
int smp_id(void);
int cpus_active(void);
void on_cpu(int cpu, void (*function)(void *data), void *data);
void on_cpu_async(int cpu, void (*function)(void *data), void *data);
void on_cpus(void (*function)(void *data), void *data);
void smp_reset_apic(void);

#endif
