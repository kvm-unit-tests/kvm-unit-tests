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

/*
 * Generic handler for decrementer exceptions (0x900)
 * Just reset the decrementer back to the value specified when registering the
 * handler
 */
void dec_except_handler(struct pt_regs *regs __unused, void *data)
{
	uint64_t dec = *((uint64_t *) data);

	asm volatile ("mtdec %0" : : "r" (dec));
}
