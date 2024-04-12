#ifndef _ASMARM_PSCI_H_
#define _ASMARM_PSCI_H_
#include <libcflat.h>
#include <linux/psci.h>

#include <asm/arm-smccc.h>

extern smccc_invoke_fn psci_invoke_fn;

extern int psci_invoke(unsigned int function_id, unsigned long arg0,
		       unsigned long arg1, unsigned long arg2);
extern void psci_set_conduit(void);
extern int psci_cpu_on(unsigned long cpuid, unsigned long entry_point);
extern void psci_system_reset(void);
extern int cpu_psci_cpu_boot(unsigned int cpu);
extern void cpu_psci_cpu_die(void);
extern void psci_system_off(void);

#endif /* _ASMARM_PSCI_H_ */
