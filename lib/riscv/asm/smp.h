/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SMP_H_
#define _ASMRISCV_SMP_H_
#include <asm/barrier.h>
#include <asm/processor.h>

#define smp_wait_for_event()	cpu_relax()
#define smp_send_event()	cpu_relax()

static inline int smp_processor_id(void)
{
	return current_thread_info()->cpu;
}

typedef void (*secondary_func_t)(void);

struct secondary_data {
	unsigned long stvec;
	secondary_func_t func;
} __attribute__((aligned(16)));

void secondary_entry(unsigned long hartid, unsigned long sp_phys);
secondary_func_t secondary_cinit(struct secondary_data *data);

void smp_boot_secondary(int cpu, void (*func)(void));
void smp_boot_secondary_nofail(int cpu, void (*func)(void));

#endif /* _ASMRISCV_SMP_H_ */
