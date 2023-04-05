// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright IBM Corp. 2023
 *
 * Test EXECUTE (RELATIVE LONG).
 * These instructions execute a target instruction. The target instruction is formed
 * by reading an instruction from memory and optionally modifying some of its bits.
 * The execution of the target instruction is the same as if it was executed
 * normally as part of the instruction sequence, except for the instruction
 * address and the instruction-length code.
 */

#include <libcflat.h>

/*
 * Accesses to the operand of execute-type instructions are instruction fetches.
 * Minimum alignment is two, since the relative offset is specified by number of halfwords.
 */
asm (  ".pushsection .text.exrl_targets,\"x\"\n"
"	.balign	2\n"
"	.popsection\n"
);

/*
 * BRANCH AND SAVE, register register variant.
 * Saves the next instruction address (address from PSW + length of instruction)
 * to the first register. No branch is taken in this test, because 0 is
 * specified as target.
 * BASR does *not* perform a relative address calculation with an intermediate.
 */
static void test_basr(void)
{
	uint64_t ret_addr, after_ex;

	report_prefix_push("BASR");
	asm volatile ( ".pushsection .text.exrl_targets\n"
		"0:	basr	%[ret_addr],0\n"
		"	.popsection\n"

		"	larl	%[after_ex],1f\n"
		"	exrl	0,0b\n"
		"1:\n"
		: [ret_addr] "=d" (ret_addr),
		  [after_ex] "=d" (after_ex)
	);

	report(ret_addr == after_ex, "return address after EX");
	report_prefix_pop();
}

/*
 * BRANCH RELATIVE AND SAVE.
 * According to PoP (Branch-Address Generation), the address calculated relative
 * to the instruction address is relative to BRAS when it is the target of an
 * execute-type instruction, not relative to the execute-type instruction.
 */
static void test_bras(void)
{
	uint64_t after_target, ret_addr, after_ex, branch_addr;

	report_prefix_push("BRAS");
	asm volatile ( ".pushsection .text.exrl_targets\n"
		"0:	bras	%[ret_addr],1f\n"
		"	nopr	%%r7\n"
		"1:	larl	%[branch_addr],0\n"
		"	j	4f\n"
		"	.popsection\n"

		"	larl	%[after_target],1b\n"
		"	larl	%[after_ex],3f\n"
		"2:	exrl	0,0b\n"
/*
 * In case the address calculation is correct, we jump by the relative offset 1b-0b from 0b to 1b.
 * In case the address calculation is relative to the exrl (i.e. a test failure),
 * put a valid instruction at the same relative offset from the exrl, so the test continues in a
 * controlled manner.
 */
		"3:	larl	%[branch_addr],0\n"
		"4:\n"

/*
 * Clang 15 doesn't like the if below, guard it s.t. we still have the assertion
 * when compiling with GCC.
 *
 * s390x/ex.c:81:4: error: expected absolute expression
 *                  "       .if (1b - 0b) != (3b - 2b)\n"
 */
#ifndef __clang__
		"	.if (1b - 0b) != (3b - 2b)\n"
		"	.error	\"right and wrong target must have same offset\"\n"
		"	.endif\n"
#endif
		: [after_target] "=d" (after_target),
		  [ret_addr] "=d" (ret_addr),
		  [after_ex] "=d" (after_ex),
		  [branch_addr] "=d" (branch_addr)
	);

	report(after_target == branch_addr, "address calculated relative to BRAS");
	report(ret_addr == after_ex, "return address after EX");
	report_prefix_pop();
}

/*
 * LOAD ADDRESS RELATIVE LONG.
 * If it is the target of an execute-type instruction, the address is relative
 * to the LARL.
 */
static void test_larl(void)
{
	uint64_t target, addr;

	report_prefix_push("LARL");
	asm volatile ( ".pushsection .text.exrl_targets\n"
		"0:	larl	%[addr],0\n"
		"	.popsection\n"

		"	larl	%[target],0b\n"
		"	exrl	0,0b\n"
		: [target] "=d" (target),
		  [addr] "=d" (addr)
	);

	report(target == addr, "address calculated relative to LARL");
	report_prefix_pop();
}

/* LOAD LOGICAL RELATIVE LONG.
 * If it is the target of an execute-type instruction, the address is relative
 * to the LLGFRL.
 */
static void test_llgfrl(void)
{
	uint64_t target, value;

	report_prefix_push("LLGFRL");
	asm volatile ( ".pushsection .text.exrl_targets\n"
		"	.balign	4\n"
		 //operand of llgfrl must be word aligned
		"0:	llgfrl	%[value],0\n"
		"	.popsection\n"

		"	llgfrl	%[target],0b\n"
		//align (pad with nop), in case the wrong operand is used
		"	.balignw 4,0x0707\n"
		"	exrl	0,0b\n"
		: [target] "=d" (target),
		  [value] "=d" (value)
	);

	report(target == value, "loaded correct value");
	report_prefix_pop();
}

/*
 * COMPARE RELATIVE LONG
 * If it is the target of an execute-type instruction, the address is relative
 * to the CRL.
 */
static void test_crl(void)
{
	uint32_t program_mask, cc, crl_word;

	report_prefix_push("CRL");
	asm volatile ( ".pushsection .text.exrl_targets\n"
		 //operand of crl must be word aligned
		 "	.balign	4\n"
		"0:	crl	%[crl_word],0\n"
		"	.popsection\n"

		"	lrl	%[crl_word],0b\n"
		//align (pad with nop), in case the wrong operand is used
		"	.balignw 4,0x0707\n"
		"	exrl	0,0b\n"
		"	ipm	%[program_mask]\n"
		: [program_mask] "=d" (program_mask),
		  [crl_word] "=d" (crl_word)
		:: "cc"
	);

	cc = program_mask >> 28;
	report(!cc, "operand compared to is relative to CRL");
	report_prefix_pop();
}

int main(int argc, char **argv)
{
	report_prefix_push("ex");
	test_basr();
	test_bras();
	test_larl();
	test_llgfrl();
	test_crl();
	report_prefix_pop();

	return report_summary();
}
