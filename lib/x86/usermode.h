#ifndef _X86_USERMODE_H_
#define _X86_USERMODE_H_

#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/apic-defs.h"
#include "x86/apic.h"
#include "x86/desc.h"
#include "x86/isr.h"
#include "alloc.h"
#include "setjmp.h"

#include "libcflat.h"
#include <stdint.h>

typedef uint64_t (*usermode_func)(void);

/*
 * Run function in user mode
 * Supports running functions with up to 4 arguments.
 * fault_vector: exception vector that might get thrown during the function.
 * raised_vector: outputs true if exception occurred.
 * ex_handler: optional handler to call when handling @fault_vector exceptions
 *
 * returns: return value returned by function, or 0 if an exception occurred.
 */
uint64_t run_in_user_ex(usermode_func func, unsigned int fault_vector,
			uint64_t arg1, uint64_t arg2, uint64_t arg3,
			uint64_t arg4, bool *raised_vector, handler ex_handler);

static inline uint64_t run_in_user(usermode_func func, unsigned int fault_vector,
				   uint64_t arg1, uint64_t arg2, uint64_t arg3,
				   uint64_t arg4, bool *raised_vector)
{
	return run_in_user_ex(func, fault_vector, arg1, arg2, arg3, arg4, raised_vector, NULL);
}
#endif
