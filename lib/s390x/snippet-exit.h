/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Functionality handling snippet exits
 *
 * Copyright IBM Corp. 2024
 */

#ifndef _S390X_SNIPPET_EXIT_H_
#define _S390X_SNIPPET_EXIT_H_

#include <libcflat.h>
#include <sie.h>
#include <sie-icpt.h>

static inline bool snippet_is_force_exit(struct vm *vm)
{
	return sie_is_diag_icpt(vm, 0x44);
}

static inline bool snippet_is_force_exit_value(struct vm *vm)
{
	return sie_is_diag_icpt(vm, 0x500);
}

static inline uint64_t snippet_get_force_exit_value(struct vm *vm)
{
	assert(snippet_is_force_exit_value(vm));

	return vm->save_area.guest.grs[2];
}

static inline void snippet_check_force_exit_value(struct vm *vm, uint64_t value_exp)
{
	uint64_t value;

	if (snippet_is_force_exit_value(vm)) {
		value = snippet_get_force_exit_value(vm);
		report(value == value_exp, "guest forced exit with value (0x%lx == 0x%lx)",
		       value, value_exp);
	} else {
		report_fail("guest forced exit with value");
	}
}

#endif /* _S390X_SNIPPET_EXIT_H_ */
