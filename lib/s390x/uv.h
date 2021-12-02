/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _S390X_UV_H_
#define _S390X_UV_H_

#include <sie.h>
#include <asm/pgtable.h>

bool uv_os_is_guest(void);
bool uv_os_is_host(void);
bool uv_query_test_call(unsigned int nr);
void uv_init(void);
int uv_setup(void);
void uv_create_guest(struct vm *vm);
void uv_destroy_guest(struct vm *vm);
int uv_unpack(struct vm *vm, uint64_t addr, uint64_t len, uint64_t tweak);
void uv_verify_load(struct vm *vm);

/*
 * To run PV guests we need to setup a few things:
 * - A valid primary ASCE that contains the guest memory and has the P bit set.
 * - A valid home space ASCE for the UV calls that use home space addresses.
 */
static inline void uv_setup_asces(void)
{
	uint64_t asce;

	/* We need to have a valid primary ASCE to run guests. */
	setup_vm();

	/* Set P bit in ASCE as it is required for PV guests */
	asce = stctg(1) | ASCE_P;
	lctlg(1, asce);

	/* Copy ASCE into home space CR */
	lctlg(13, asce);
}

#endif /* UV_H */
