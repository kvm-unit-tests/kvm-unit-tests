/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Arm Limited.
 * All rights reserved.
 */

#include <libcflat.h>
#include <asm/smp.h>
#include <stdlib.h>

#define CPU0_ID			0
#define CPU1_ID			(CPU0_ID + 1)
#define CPUS_MAX		(CPU1_ID + 1)
#define FPU_QREG_MAX	32
#define FPU_RESULT_PASS	(-1U)

/*
 * Write 8 bytes of random data in random. Returns true on success, false on
 * failure.
 */
static inline bool arch_collect_entropy(uint64_t *random)
{
	unsigned long ret;

	asm volatile(
	"	mrs  %[ptr], " xstr(RNDR) "\n"
	"	cset %[ret], ne\n" /* RNDR sets NZCV to 0b0100 on failure */
	:
	  [ret] "=r" (ret),
	  [ptr] "=r" (*random)
	:
	: "cc"
	);

	return ret == 1;
}

#define fpu_reg_read(val)				\
({							\
	uint64_t *__val = (val);			\
	asm volatile(".arch_extension fp\n"		\
		     "stp q0, q1, [%0], #32\n\t"	\
		     "stp q2, q3, [%0], #32\n\t"	\
		     "stp q4, q5, [%0], #32\n\t"	\
		     "stp q6, q7, [%0], #32\n\t"	\
		     "stp q8, q9, [%0], #32\n\t"	\
		     "stp q10, q11, [%0], #32\n\t"	\
		     "stp q12, q13, [%0], #32\n\t"	\
		     "stp q14, q15, [%0], #32\n\t"	\
		     "stp q16, q17, [%0], #32\n\t"	\
		     "stp q18, q19, [%0], #32\n\t"	\
		     "stp q20, q21, [%0], #32\n\t"	\
		     "stp q22, q23, [%0], #32\n\t"	\
		     "stp q24, q25, [%0], #32\n\t"	\
		     "stp q26, q27, [%0], #32\n\t"	\
		     "stp q28, q29, [%0], #32\n\t"	\
		     "stp q30, q31, [%0], #32\n\t"	\
		     : "+r" (__val)			\
		     :					\
		     : "v0", "v1", "v2", "v3",		\
			"v4", "v5", "v6", "v7",		\
			"v8", "v9", "v10", "v11",	\
			"v12", "v13", "v14",		\
			"v15", "v16", "v17",		\
			"v18", "v19", "v20",		\
			"v21", "v22", "v23",		\
			"v24", "v25", "v26",		\
			"v27", "v28", "v29",		\
			"v30", "v31", "memory");	\
})

#define fpu_reg_write(val)				\
do {							\
	uint64_t *__val = (val);			\
	asm volatile(".arch_extension fp\n"		\
		     "ldp q0, q1, [%0], #32\n\t"	\
		     "ldp q2, q3, [%0], #32\n\t"	\
		     "ldp q4, q5, [%0], #32\n\t"	\
		     "ldp q6, q7, [%0], #32\n\t"	\
		     "ldp q8, q9, [%0], #32\n\t"	\
		     "ldp q10, q11, [%0], #32\n\t"	\
		     "ldp q12, q13, [%0], #32\n\t"	\
		     "ldp q14, q15, [%0], #32\n\t"	\
		     "ldp q16, q17, [%0], #32\n\t"	\
		     "ldp q18, q19, [%0], #32\n\t"	\
		     "ldp q20, q21, [%0], #32\n\t"	\
		     "ldp q22, q23, [%0], #32\n\t"	\
		     "ldp q24, q25, [%0], #32\n\t"	\
		     "ldp q26, q27, [%0], #32\n\t"	\
		     "ldp q28, q29, [%0], #32\n\t"	\
		     "ldp q30, q31, [%0], #32\n\t"	\
		     : "+r" (__val)			\
		     :					\
		     : "v0", "v1", "v2", "v3",		\
			"v4", "v5", "v6", "v7",		\
			"v8", "v9", "v10", "v11",	\
			"v12", "v13", "v14",		\
			"v15", "v16", "v17",		\
			"v18", "v19", "v20",		\
			"v21", "v22", "v23",		\
			"v24", "v25", "v26",		\
			"v27", "v28", "v29",		\
			"v30", "v31", "memory");	\
} while (0)

#ifdef CC_HAS_SVE
#define sve_reg_read(val)				\
({							\
	uint64_t *__val = (val);			\
	asm volatile(".arch_extension sve\n"		\
		     "str z0, [%0, #0, MUL VL]\n"	\
		     "str z1, [%0, #1, MUL VL]\n"	\
		     "str z2, [%0, #2, MUL VL]\n"	\
		     "str z3, [%0, #3, MUL VL]\n"	\
		     "str z4, [%0, #4, MUL VL]\n"	\
		     "str z5, [%0, #5, MUL VL]\n"	\
		     "str z6, [%0, #6, MUL VL]\n"	\
		     "str z7, [%0, #7, MUL VL]\n"	\
		     "str z8, [%0, #8, MUL VL]\n"	\
		     "str z9, [%0, #9, MUL VL]\n"	\
		     "str z10, [%0, #10, MUL VL]\n"	\
		     "str z11, [%0, #11, MUL VL]\n"	\
		     "str z12, [%0, #12, MUL VL]\n"	\
		     "str z13, [%0, #13, MUL VL]\n"	\
		     "str z14, [%0, #14, MUL VL]\n"	\
		     "str z15, [%0, #15, MUL VL]\n"	\
		     "str z16, [%0, #16, MUL VL]\n"	\
		     "str z17, [%0, #17, MUL VL]\n"	\
		     "str z18, [%0, #18, MUL VL]\n"	\
		     "str z19, [%0, #19, MUL VL]\n"	\
		     "str z20, [%0, #20, MUL VL]\n"	\
		     "str z21, [%0, #21, MUL VL]\n"	\
		     "str z22, [%0, #22, MUL VL]\n"	\
		     "str z23, [%0, #23, MUL VL]\n"	\
		     "str z24, [%0, #24, MUL VL]\n"	\
		     "str z25, [%0, #25, MUL VL]\n"	\
		     "str z26, [%0, #26, MUL VL]\n"	\
		     "str z27, [%0, #27, MUL VL]\n"	\
		     "str z28, [%0, #28, MUL VL]\n"	\
		     "str z29, [%0, #29, MUL VL]\n"	\
		     "str z30, [%0, #30, MUL VL]\n"	\
		     "str z31, [%0, #31, MUL VL]\n"	\
		     :					\
		     : "r" (__val)			\
		     : "z0", "z1", "z2", "z3",		\
			"z4", "z5", "z6", "z7",		\
			"z8", "z9", "z10", "z11",	\
			"z12", "z13", "z14",		\
			"z15", "z16", "z17",		\
			"z18", "z19", "z20",		\
			"z21", "z22", "z23",		\
			"z24", "z25", "z26",		\
			"z27", "z28", "z29",		\
			"z30", "z31", "memory");	\
})

#define sve_reg_write(val)				\
({							\
	uint64_t *__val = (val);			\
	asm volatile(".arch_extension sve\n"		\
		     "ldr z0, [%0, #0, MUL VL]\n"	\
		     "ldr z1, [%0, #1, MUL VL]\n"	\
		     "ldr z2, [%0, #2, MUL VL]\n"	\
		     "ldr z3, [%0, #3, MUL VL]\n"	\
		     "ldr z4, [%0, #4, MUL VL]\n"	\
		     "ldr z5, [%0, #5, MUL VL]\n"	\
		     "ldr z6, [%0, #6, MUL VL]\n"	\
		     "ldr z7, [%0, #7, MUL VL]\n"	\
		     "ldr z8, [%0, #8, MUL VL]\n"	\
		     "ldr z9, [%0, #9, MUL VL]\n"	\
		     "ldr z10, [%0, #10, MUL VL]\n"	\
		     "ldr z11, [%0, #11, MUL VL]\n"	\
		     "ldr z12, [%0, #12, MUL VL]\n"	\
		     "ldr z13, [%0, #13, MUL VL]\n"	\
		     "ldr z14, [%0, #14, MUL VL]\n"	\
		     "ldr z15, [%0, #15, MUL VL]\n"	\
		     "ldr z16, [%0, #16, MUL VL]\n"	\
		     "ldr z17, [%0, #17, MUL VL]\n"	\
		     "ldr z18, [%0, #18, MUL VL]\n"	\
		     "ldr z19, [%0, #19, MUL VL]\n"	\
		     "ldr z20, [%0, #20, MUL VL]\n"	\
		     "ldr z21, [%0, #21, MUL VL]\n"	\
		     "ldr z22, [%0, #22, MUL VL]\n"	\
		     "ldr z23, [%0, #23, MUL VL]\n"	\
		     "ldr z24, [%0, #24, MUL VL]\n"	\
		     "ldr z25, [%0, #25, MUL VL]\n"	\
		     "ldr z26, [%0, #26, MUL VL]\n"	\
		     "ldr z27, [%0, #27, MUL VL]\n"	\
		     "ldr z28, [%0, #28, MUL VL]\n"	\
		     "ldr z29, [%0, #29, MUL VL]\n"	\
		     "ldr z30, [%0, #30, MUL VL]\n"	\
		     "ldr z31, [%0, #31, MUL VL]\n"	\
		     :					\
		     : "r" (__val)			\
		     : "z0", "z1", "z2", "z3",		\
			"z4", "z5", "z6", "z7",		\
			"z8", "z9", "z10", "z11",	\
			"z12", "z13", "z14",		\
			"z15", "z16", "z17",		\
			"z18", "z19", "z20",		\
			"z21", "z22", "z23",		\
			"z24", "z25", "z26",		\
			"z27", "z28", "z29",		\
			"z30", "z31", "memory");	\
})
#else
#define sve_reg_read(val)	report_abort("SVE: not supported")
#define sve_reg_write(val)	report_abort("SVE: not supported")
#endif

static void nr_cpu_check(int nr)
{
	if (nr_cpus < nr)
		report_abort("At least %d cpus required", nr);
}

/*
 * check if the FPU/SIMD/SVE register contents are the same as
 * the input data provided.
 */
static uint32_t __fpuregs_testall(uint64_t *indata, int sve)
{
	/* 128b aligned array to read data into */
	uint64_t outdata[FPU_QREG_MAX * 2]
			 __attribute__((aligned(sizeof(__uint128_t)))) = {
			[0 ... ((FPU_QREG_MAX * 2) - 1)] = 0 };
	uint8_t regcnt	= 0;
	uint32_t result	= 0;

	if (indata == NULL)
		report_abort("invalid data pointer received");

	/* Read data from FPU/SVE registers */
	if (sve)
		sve_reg_read(outdata);
	else
		fpu_reg_read(outdata);

	/* Check is the data is the same */
	for (regcnt = 0; regcnt < (FPU_QREG_MAX * 2); regcnt += 2) {
		if ((outdata[regcnt] != indata[regcnt]) ||
			(outdata[regcnt + 1] != indata[regcnt + 1])) {
			report_info(
			"%s save/restore failed for reg: %c%u expected: %lx_%lx received: %lx_%lx\n",
			sve ? "SVE" : "FPU/SIMD",
			sve ? 'z' : 'q',
			regcnt / 2,
			indata[regcnt + 1], indata[regcnt],
			outdata[regcnt + 1], outdata[regcnt]);
		} else {
			/* populate a bitmask indicating which
			 * registers passed/failed
			 */
			result |= (1 << (regcnt / 2));
		}
	}

	return result;
}

/*
 * Write randomly sampled data into the FPU/SIMD registers.
 */
static void __fpuregs_writeall_random(uint64_t **indata, int sve)
{
	/* allocate 128b aligned memory */
	*indata = memalign(sizeof(__uint128_t), sizeof(uint64_t) * FPU_QREG_MAX);

	if (system_supports_rndr()) {
		/* Populate memory with random data */
		for (unsigned int i = 0; i < (FPU_QREG_MAX * 2); i++)
			while (!arch_collect_entropy(&(*indata)[i])) {}
	} else {
		/* Populate memory with data from the counter register */
		for (unsigned int i = 0; i < (FPU_QREG_MAX * 2); i++)
			(*indata)[i] = get_cntvct();
	}

	/* Write data into FPU registers */
	if (sve)
		sve_reg_write(*indata);
	else
		fpu_reg_write(*indata);
}

static void fpuregs_writeall_run(void *data)
{
	uint64_t **indata	= (uint64_t **)data;

	__fpuregs_writeall_random(indata, 0);
}

static void sveregs_writeall_run(void *data)
{
	uint64_t **indata	= (uint64_t **)data;

	__fpuregs_writeall_random(indata, 1);
}

static void fpuregs_testall_run(void *data)
{
	uint64_t *indata	= (uint64_t *)data;
	uint32_t result		= 0;

	result = __fpuregs_testall(indata, 0);
	report((result == FPU_RESULT_PASS),
	       "FPU/SIMD register save/restore mask: 0x%x", result);
}

static void sveregs_testall_run(void *data)
{
	uint64_t *indata	= (uint64_t *)data;
	uint32_t result		= 0;

	result = __fpuregs_testall(indata, 1);
	report((result == FPU_RESULT_PASS),
	       "SVE register save/restore mask: 0x%x", result);
}

/*
 * This test uses two CPUs to test FPU/SIMD save/restore
 * CPU1 writes random data into FPU/SIMD registers,
 * CPU0 corrupts/overwrites the data and finally CPU1 checks
 * if the data remains unchanged in its context.
 */
static void fpuregs_context_switch_cpu1(int sve)
{
	int target		= CPU1_ID;
	uint64_t *indata_remote	= NULL;
	uint64_t *indata_local	= NULL;

	/* write data from CPU1 */
	on_cpu(target, sve ? sveregs_writeall_run
	                   : fpuregs_writeall_run,
	       &indata_remote);

	/* Overwrite from CPU0 */
	__fpuregs_writeall_random(&indata_local, sve);

	/* Check data consistency */
	on_cpu(target, sve ? sveregs_testall_run
	                   : fpuregs_testall_run,
	       indata_remote);

	free(indata_remote);
	free(indata_local);
}

/*
 * This test uses two CPUs to test FPU/SIMD save/restore
 * CPU0 writes random data into FPU/SIMD registers,
 * CPU1 corrupts/overwrites the data and finally CPU0 checks if
 * the data remains unchanged in its context.
 */
static void fpuregs_context_switch_cpu0(int sve)
{
	int target		= CPU1_ID;
	uint64_t *indata_local	= NULL;
	uint64_t *indata_remote	= NULL;
	uint32_t result		= 0;

	/* write data from CPU0 */
	__fpuregs_writeall_random(&indata_local, sve);

	/* Overwrite from CPU1 */
	on_cpu(target, sve ? sveregs_writeall_run
	                   : fpuregs_writeall_run,
	       &indata_remote);

	/* Check data consistency */
	result = __fpuregs_testall(indata_local, sve);
	report((result == FPU_RESULT_PASS),
	       "%s register save/restore mask: 0x%x", sve ? "SVE" : "FPU/SIMD", result);

	free(indata_remote);
	free(indata_local);
}

/*
 * Checks if during context switch, FPU/SIMD registers
 * are saved/restored.
 */
static void fpuregs_context_switch(void)
{
	fpuregs_context_switch_cpu0(0);
	fpuregs_context_switch_cpu1(0);
}

/*
 * Checks if during context switch, SVE registers
 * are saved/restored.
 */
static void sveregs_context_switch(void)
{
	unsigned long zcr = read_sysreg(ZCR_EL1);

	// Set the SVE vector length to 128-bits
	write_sysreg(zcr & ~ZCR_EL1_LEN, ZCR_EL1);

	fpuregs_context_switch_cpu0(1);
	fpuregs_context_switch_cpu1(1);
}

static bool should_run_sve_tests(void)
{
#ifdef CC_HAS_SVE
	if (system_supports_sve())
		return true;
#endif
	return false;
}

int main(int argc, char **argv)
{
	report_prefix_pushf("fpu");

	nr_cpu_check(CPUS_MAX);
	fpuregs_context_switch();

	if (should_run_sve_tests())
		sveregs_context_switch();

	return report_summary();
}
