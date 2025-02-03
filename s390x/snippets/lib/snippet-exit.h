/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Functionality for exiting the snippet.
 *
 * Copyright IBM Corp. 2023
 */

#ifndef _S390X_SNIPPET_LIB_EXIT_H_
#define _S390X_SNIPPET_LIB_EXIT_H_

#include <asm/arch_def.h>
#include <asm/barrier.h>

static inline void force_exit(void)
{
	mb(); /* host may read any memory written by the guest before */
	diag44();
	mb(); /* allow host to modify guest memory */
}

static inline void force_exit_value(uint64_t val)
{
	mb(); /* host may read any memory written by the guest before */
	diag500(val);
	mb(); /* allow host to modify guest memory */
}

#endif /* _S390X_SNIPPET_LIB_EXIT_H_ */
