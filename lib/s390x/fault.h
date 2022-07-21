/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Headers for fault.c
 *
 * Copyright 2021 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#ifndef _S390X_FAULT_H_
#define _S390X_FAULT_H_

#include <bitops.h>
#include <asm/facility.h>
#include <asm/interrupt.h>

/* Instruction execution prevention, i.e. no-execute, 101 */
static inline bool prot_is_iep(union teid teid)
{
	if (!test_facility(130))
		return false;
	/* IEP installed -> ESOP2 installed */
	return teid_esop2_prot_code(teid) == PROT_IEP;
}

void print_decode_teid(uint64_t teid);

#endif /* _S390X_FAULT_H_ */
