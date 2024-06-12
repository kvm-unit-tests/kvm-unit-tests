#ifndef _ASMPOWERPC_SMP_H_
#define _ASMPOWERPC_SMP_H_

#include <libcflat.h>
#include <asm/processor.h>
#include <asm/page.h>

typedef void (*secondary_entry_fn)(int cpu_id);

struct cpu {
	unsigned long server_no;
	unsigned long stack;
	unsigned long exception_stack;
	bool in_user;
	secondary_entry_fn entry;
	pgd_t *pgtable;
};

extern int nr_cpus_present;
extern int nr_cpus_online;
extern struct cpu cpus[];

register struct cpu *__current_cpu asm("r13");
static inline struct cpu *current_cpu(void)
{
	return __current_cpu;
}

static inline int smp_processor_id(void)
{
	return current_cpu()->server_no;
}

void cpu_init(struct cpu *cpu, int cpu_id);

extern void halt(int cpu_id);

extern bool start_all_cpus(secondary_entry_fn entry);
extern void stop_all_cpus(void);

struct pt_regs;
void register_ipi(void (*fn)(struct pt_regs *, void *), void *data);
void unregister_ipi(void);
void cpu_init_ipis(void);
void local_ipi_enable(void);
void local_ipi_disable(void);
void send_ipi(int cpu_id);

#endif /* _ASMPOWERPC_SMP_H_ */
