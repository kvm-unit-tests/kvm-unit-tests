/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SETUP_H_
#define _ASMRISCV_SETUP_H_
#include <libcflat.h>
#include <asm/processor.h>

#define NR_CPUS 256
extern struct thread_info cpus[NR_CPUS];
extern int nr_cpus;
extern uint64_t timebase_frequency;
int hartid_to_cpu(unsigned long hartid);

void io_init(void);
void setup(const void *fdt, phys_addr_t freemem_start);

#ifdef CONFIG_EFI
#include <efi.h>
efi_status_t setup_efi(efi_bootinfo_t *efi_bootinfo);
#endif

#endif /* _ASMRISCV_SETUP_H_ */
