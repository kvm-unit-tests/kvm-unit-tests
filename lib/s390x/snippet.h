/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Snippet definitions
 *
 * Copyright IBM Corp. 2021
 * Author: Janosch Frank <frankja@linux.ibm.com>
 */

#ifndef _S390X_SNIPPET_H_
#define _S390X_SNIPPET_H_

/* This macro cuts down the length of the pointers to snippets */
#define SNIPPET_NAME_START(type, file) \
	_binary_s390x_snippets_##type##_##file##_gbin_start
#define SNIPPET_NAME_END(type, file) \
	_binary_s390x_snippets_##type##_##file##_gbin_end

/* Returns the length of the snippet */
#define SNIPPET_LEN(type, file) \
	((uintptr_t)SNIPPET_NAME_END(type, file) - (uintptr_t)SNIPPET_NAME_START(type, file))

/*
 * C snippet instructions start at 0x4000 due to the prefix and the
 * stack being before that. ASM snippets don't strictly need a stack
 * but keeping the starting address the same means less code.
 */
#define SNIPPET_ENTRY_ADDR 0x4000

/* Standard entry PSWs for snippets which can simply be copied into the guest PSW */
static const struct psw snippet_psw = {
	.mask = PSW_MASK_64,
	.addr = SNIPPET_ENTRY_ADDR,
};
#endif
