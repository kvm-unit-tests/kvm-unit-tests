/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Helper assembly code routines for RISC-V SBI extension tests.
 *
 * Copyright (C) 2024, James Raphael Tiovalen <jamestiotio@gmail.com>
 */
#define __ASSEMBLY__
#include <asm/asm.h>
#include <asm/csr.h>

#include "sbi-tests.h"

.section .text

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
