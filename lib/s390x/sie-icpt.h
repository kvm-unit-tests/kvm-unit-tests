/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Functionality for SIE interception handling.
 *
 * Copyright IBM Corp. 2024
 */

#ifndef _S390X_SIE_ICPT_H_
#define _S390X_SIE_ICPT_H_

#include <libcflat.h>
#include <sie.h>

struct diag_itext {
	uint64_t opcode   :  8;
	uint64_t r_1      :  4;
	uint64_t r_2      :  4;
	uint64_t r_base   :  4;
	uint64_t displace : 12;
	uint64_t zero     : 16;
	uint64_t          : 16;
};

struct diag_itext sblk_ip_as_diag(struct kvm_s390_sie_block *sblk);

/**
 * sie_is_diag_icpt() - Check if intercept is due to diagnose instruction
 * @vm: the guest
 * @diag: the expected diagnose code
 *
 * Check that the intercept is due to diagnose @diag and valid.
 * For protected virtualization, check that the intercept data meets additional
 * constraints.
 *
 * Returns: true if intercept is due to a valid and has matching diagnose code
 */
bool sie_is_diag_icpt(struct vm *vm, unsigned int diag);

#endif /* _S390X_SIE_ICPT_H_ */
