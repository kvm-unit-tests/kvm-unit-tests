/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Helper assembly code routines for RISC-V SBI extension tests.
 *
 * Copyright (C) 2024, James Raphael Tiovalen <jamestiotio@gmail.com>
 */
#include <asm/asm.h>
#include <asm/csr.h>
#include <asm/asm-offsets.h>
#include <generated/sbi-asm-offsets.h>

#include "sbi-tests.h"

.section .text

/*
 * sbi_hsm_check
 *   a0 and a1 are set by SBI HSM start/suspend
 *   s1 is the address of the results array
 * Doesn't return.
 *
 * This function is only called from HSM start and on resumption
 * from HSM suspend which means we can do whatever we like with
 * all registers. So, to avoid complicated register agreements with
 * other assembly functions called, we just always use the saved
 * registers for anything that should be maintained across calls.
 */
#define HSM_RESULTS_ARRAY	s1
#define HSM_RESULTS_MAP		s2
#define HSM_CPU_INDEX		s3
.balign 4
sbi_hsm_check:
	li	HSM_RESULTS_MAP, 0
	REG_L	t0, ASMARR(a1, SBI_HSM_MAGIC_IDX)
	li	t1, SBI_HSM_MAGIC
	bne	t0, t1, 1f
	ori	HSM_RESULTS_MAP, HSM_RESULTS_MAP, SBI_HSM_TEST_MAGIC_A1
1:	REG_L	t0, ASMARR(a1, SBI_HSM_HARTID_IDX)
	bne	a0, t0, 2f
	ori	HSM_RESULTS_MAP, HSM_RESULTS_MAP, SBI_HSM_TEST_HARTID_A0
2:	csrr	t0, CSR_SATP
	bnez	t0, 3f
	ori	HSM_RESULTS_MAP, HSM_RESULTS_MAP, SBI_HSM_TEST_SATP
3:	csrr	t0, CSR_SSTATUS
	andi	t0, t0, SR_SIE
	bnez	t0, 4f
	ori	HSM_RESULTS_MAP, HSM_RESULTS_MAP, SBI_HSM_TEST_SIE
4:	call	hartid_to_cpu
	mv	HSM_CPU_INDEX, a0
	li	t0, -1
	bne	HSM_CPU_INDEX, t0, 6f
5:	pause
	j	5b
6:	ori	HSM_RESULTS_MAP, HSM_RESULTS_MAP, SBI_HSM_TEST_DONE
	add	t0, HSM_RESULTS_ARRAY, HSM_CPU_INDEX
	sb	HSM_RESULTS_MAP, 0(t0)
	la	t1, sbi_hsm_stop_hart
	add	t1, t1, HSM_CPU_INDEX
7:	lb	t0, 0(t1)
	pause
	beqz	t0, 7b
	li	a7, ASM_SBI_EXT_HSM
	li	a6, ASM_SBI_EXT_HSM_HART_STOP
	ecall
8:	pause
	j	8b

.balign 4
.global sbi_hsm_check_hart_start
sbi_hsm_check_hart_start:
	la	HSM_RESULTS_ARRAY, sbi_hsm_hart_start_checks
	j	sbi_hsm_check

.balign 4
.global sbi_hsm_check_non_retentive_suspend
sbi_hsm_check_non_retentive_suspend:
	la	HSM_RESULTS_ARRAY, sbi_hsm_non_retentive_hart_suspend_checks
	j	sbi_hsm_check

.balign 4
restore_csrs:
	REG_L	a1, ASMARR(a0, SBI_CSR_SSTATUS_IDX)
	csrw	CSR_SSTATUS, a1
	REG_L	a1, ASMARR(a0, SBI_CSR_SIE_IDX)
	csrw	CSR_SIE, a1
	REG_L	a1, ASMARR(a0, SBI_CSR_STVEC_IDX)
	csrw	CSR_STVEC, a1
	REG_L	a1, ASMARR(a0, SBI_CSR_SSCRATCH_IDX)
	csrw	CSR_SSCRATCH, a1
	REG_L	a1, ASMARR(a0, SBI_CSR_SATP_IDX)
	sfence.vma
	csrw	CSR_SATP, a1
	ret

/*
 * sbi_susp_resume
 *
 * State is as specified by "SUSP System Resume Register State" of the SBI spec
 *   a0 is the hartid
 *   a1 is the opaque parameter (here, it's the context array defined in check_susp())
 * Doesn't return.
 */
#define SUSP_CTX		s1
#define SUSP_RESULTS_MAP	s2
.balign 4
.global sbi_susp_resume
sbi_susp_resume:
	li	SUSP_RESULTS_MAP, 0
	mv	SUSP_CTX, a1
	REG_L	t0, ASMARR(SUSP_CTX, SBI_SUSP_MAGIC_IDX)
	li	t1, SBI_SUSP_MAGIC
	beq	t0, t1, 2f
1:	pause
	j	1b
2:	csrr	t0, CSR_SATP
	bnez	t0, 3f
	ori	SUSP_RESULTS_MAP, SUSP_RESULTS_MAP, SBI_SUSP_TEST_SATP
3:	csrr	t0, CSR_SSTATUS
	andi	t0, t0, SR_SIE
	bnez	t0, 4f
	ori	SUSP_RESULTS_MAP, SUSP_RESULTS_MAP, SBI_SUSP_TEST_SIE
4:	REG_L	t0, ASMARR(SUSP_CTX, SBI_SUSP_HARTID_IDX)
	bne	t0, a0, 5f
	ori	SUSP_RESULTS_MAP, SUSP_RESULTS_MAP, SBI_SUSP_TEST_HARTID
5:	REG_S	SUSP_RESULTS_MAP, ASMARR(SUSP_CTX, SBI_SUSP_RESULTS_IDX)
	REG_L	a0, ASMARR(SUSP_CTX, SBI_SUSP_CSRS_IDX)
	call	restore_csrs
	la	a0, sbi_susp_jmp
	REG_L	a1, ASMARR(SUSP_CTX, SBI_SUSP_TESTNUM_IDX)
	call	longjmp
6:	pause	/* unreachable */
	j	6b
