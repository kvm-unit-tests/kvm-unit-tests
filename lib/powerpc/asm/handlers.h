#ifndef _ASMPOWERPC_HANDLERS_H_
#define _ASMPOWERPC_HANDLERS_H_

#include <asm/ptrace.h>

void dec_handler_oneshot(struct pt_regs *regs, void *data);

#endif /* _ASMPOWERPC_HANDLERS_H_ */
