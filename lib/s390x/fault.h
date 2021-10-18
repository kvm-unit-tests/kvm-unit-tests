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

/* Instruction execution prevention, i.e. no-execute, 101 */
static inline bool prot_is_iep(uint64_t teid)
{
	if (test_bit_inv(56, &teid) && !test_bit_inv(60, &teid) && test_bit_inv(61, &teid))
		return true;

	return false;
}

/* Standard DAT exception, 001 */
static inline bool prot_is_datp(uint64_t teid)
{
	if (!test_bit_inv(56, &teid) && !test_bit_inv(60, &teid) && test_bit_inv(61, &teid))
		return true;

	return false;
}

/* Low-address protection exception, 100 */
static inline bool prot_is_lap(uint64_t teid)
{
	if (test_bit_inv(56, &teid) && !test_bit_inv(60, &teid) && !test_bit_inv(61, &teid))
		return true;

	return false;
}

void print_decode_teid(uint64_t teid);

#endif /* _S390X_FAULT_H_ */
