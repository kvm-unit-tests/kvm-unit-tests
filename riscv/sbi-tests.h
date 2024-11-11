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

#define SBI_CSR_SSTATUS_IDX	0
#define SBI_CSR_SIE_IDX		1
#define SBI_CSR_STVEC_IDX	2
#define SBI_CSR_SSCRATCH_IDX	3
#define SBI_CSR_SATP_IDX	4

#define SBI_SUSP_MAGIC		0x505b

#define SBI_SUSP_TEST_SATP	(1 << 0)
#define SBI_SUSP_TEST_SIE	(1 << 1)
#define SBI_SUSP_TEST_HARTID	(1 << 2)
#define SBI_SUSP_TEST_MASK	7

#endif /* _RISCV_SBI_TESTS_H_ */
