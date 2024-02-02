/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SETUP_H_
#define _ASMRISCV_SETUP_H_
#include <libcflat.h>
#include <asm/processor.h>

#define NR_CPUS 16
extern struct thread_info cpus[NR_CPUS];
extern int nr_cpus;
int hartid_to_cpu(unsigned long hartid);

void io_init(void);
void setup(const void *fdt, phys_addr_t freemem_start);

#endif /* _ASMRISCV_SETUP_H_ */
