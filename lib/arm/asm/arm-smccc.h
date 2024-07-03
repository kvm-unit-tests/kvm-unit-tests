/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Arm Limited.
 * All rights reserved.
 */
#ifndef _ASMARM_ARM_SMCCC_H_
#define _ASMARM_ARM_SMCCC_H_

struct smccc_result {
	unsigned long r0;
	unsigned long r1;
	unsigned long r2;
	unsigned long r3;
	unsigned long r4;
	unsigned long r5;
	unsigned long r6;
	unsigned long r7;
	unsigned long r8;
	unsigned long r9;
};

typedef int (*smccc_invoke_fn)(unsigned int function_id, unsigned long arg0,
			       unsigned long arg1, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5, unsigned long arg6,
			       unsigned long arg7, unsigned long arg8,
			       unsigned long arg9, unsigned long arg10,
			       struct smccc_result *result);
extern int arm_smccc_hvc(unsigned int function_id, unsigned long arg0,
			 unsigned long arg1, unsigned long arg2,
			 unsigned long arg3, unsigned long arg4,
			 unsigned long arg5, unsigned long arg6,
			 unsigned long arg7, unsigned long arg8,
			 unsigned long arg9, unsigned long arg10,
			 struct smccc_result *result);
extern int arm_smccc_smc(unsigned int function_id, unsigned long arg0,
			 unsigned long arg1, unsigned long arg2,
			 unsigned long arg3, unsigned long arg4,
			 unsigned long arg5, unsigned long arg6,
			 unsigned long arg7, unsigned long arg8,
			 unsigned long arg9, unsigned long arg10,
			 struct smccc_result *result);

#endif /* _ASMARM_ARM_SMCCC_H_ */
