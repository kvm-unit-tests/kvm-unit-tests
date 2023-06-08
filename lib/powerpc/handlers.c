/*
 * Generic exception handlers for registration and use in tests
 *
 * Copyright 2016 Suraj Jitindar Singh, IBM.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#include <libcflat.h>
#include <asm/handlers.h>
#include <asm/ptrace.h>
#include <asm/ppc_asm.h>

/*
 * Generic handler for decrementer exceptions (0x900)
 * Return with MSR[EE] disabled.
 */
void dec_handler_oneshot(struct pt_regs *regs, void *data)
{
	regs->msr &= ~(1UL << MSR_EE_BIT);
}
