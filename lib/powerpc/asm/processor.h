#ifndef _ASMPOWERPC_PROCESSOR_H_
#define _ASMPOWERPC_PROCESSOR_H_

#include <asm/ptrace.h>

#ifndef __ASSEMBLY__
void handle_exception(int trap, void (*func)(struct pt_regs *, void *), void *);
void do_handle_exception(struct pt_regs *regs);
#endif /* __ASSEMBLY__ */

#endif /* _ASMPOWERPC_PROCESSOR_H_ */
