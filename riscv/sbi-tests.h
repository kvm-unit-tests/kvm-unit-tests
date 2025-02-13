/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RISCV_SBI_TESTS_H_
#define _RISCV_SBI_TESTS_H_

#define SBI_HSM_TEST_DONE	(1 << 0)
#define SBI_HSM_TEST_MAGIC_A1	(1 << 1)
#define SBI_HSM_TEST_HARTID_A0	(1 << 2)
#define SBI_HSM_TEST_SATP	(1 << 3)
#define SBI_HSM_TEST_SIE	(1 << 4)

#define SBI_HSM_MAGIC		0x453

#define SBI_HSM_MAGIC_IDX	0
#define SBI_HSM_HARTID_IDX	1
#define SBI_HSM_NUM_OF_PARAMS	2

#define SBI_SUSP_MAGIC_IDX	0
#define SBI_SUSP_CSRS_IDX	1
#define SBI_SUSP_HARTID_IDX	2
#define SBI_SUSP_TESTNUM_IDX	3
#define SBI_SUSP_RESULTS_IDX	4
#define SBI_SUSP_NR_IDX		5

#define SBI_CSR_SSTATUS_IDX	0
#define SBI_CSR_SIE_IDX		1
#define SBI_CSR_STVEC_IDX	2
#define SBI_CSR_SSCRATCH_IDX	3
#define SBI_CSR_SATP_IDX	4
#define SBI_CSR_NR_IDX		5

#define SBI_SUSP_MAGIC		0x505b

#define SBI_SUSP_TEST_SATP	(1 << 0)
#define SBI_SUSP_TEST_SIE	(1 << 1)
#define SBI_SUSP_TEST_HARTID	(1 << 2)
#define SBI_SUSP_TEST_MASK	7

#ifndef __ASSEMBLY__
#include <asm/sbi.h>

#define __sbiret_report(ret, expected_error, expected_value, has_value, expected_error_name, fmt, ...) ({	\
	long ex_err = expected_error;										\
	long ex_val = expected_value;										\
	bool has_val = !!(has_value);										\
	bool ch_err = (ret)->error == ex_err;									\
	bool ch_val = (ret)->value == ex_val;									\
	bool pass;												\
														\
	if (has_val)												\
		pass = report(ch_err && ch_val, fmt, ##__VA_ARGS__);						\
	else													\
		pass = report(ch_err, fmt ": %s", ##__VA_ARGS__, expected_error_name);				\
														\
	if (!pass && has_val)											\
		report_info(fmt ": expected (error: %ld, value: %ld), received: (error: %ld, value %ld)",	\
			    ##__VA_ARGS__, ex_err, ex_val, (ret)->error, (ret)->value);				\
	else if (!pass)												\
		report_info(fmt ": %s (%ld): received error %ld",						\
			    ##__VA_ARGS__, expected_error_name, ex_err, (ret)->error);				\
														\
	pass;													\
})

#define sbiret_report(ret, expected_error, expected_value, ...) \
	__sbiret_report(ret, expected_error, expected_value, true, #expected_error, __VA_ARGS__)

#define sbiret_report_error(ret, expected_error, ...) \
	__sbiret_report(ret, expected_error, 0, false, #expected_error, __VA_ARGS__)

#define sbiret_check(ret, expected_error, expected_value) \
	sbiret_report(ret, expected_error, expected_value, "check sbi.error and sbi.value")

#endif /* __ASSEMBLY__ */
#endif /* _RISCV_SBI_TESTS_H_ */
