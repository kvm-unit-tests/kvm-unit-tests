/*
 * Emulator tests - for s390x CPU instructions that are usually interpreted
 *                  by the hardware
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#include <libcflat.h>
#include <asm/cpacf.h>
#include <asm/interrupt.h>

static inline void __test_spm_ipm(uint8_t cc, uint8_t key)
{
	uint64_t in = (cc << 28) | (key << 24);
	uint64_t out = ~0ULL;

	report_prefix_pushf("cc=%d,key=%x", cc, key);

	asm volatile ("spm %1\n"
		      "ipm %0\n"
		      : "+r"(out) : "r"(in) : "cc");

	report("bit 32 and 33 set to zero", !(out & 0xc0000000UL));
	report("bit 0-31, 40-63 unchanged",
		(out & ~0xff000000ULL) == ~0xff000000ULL);
	report("cc and key applied", !((in ^ out) & 0x3f000000UL));

	report_prefix_pop();
}

/* Test the SET PROGRAM PARAMETER and INSERT PROGRAM PARAMETER instruction */
static void test_spm_ipm(void)
{
	__test_spm_ipm(0, 0xf);
	__test_spm_ipm(1, 0x9);
	__test_spm_ipm(2, 0x5);
	__test_spm_ipm(3, 0x3);
	__test_spm_ipm(0, 0);
}

static inline void __test_cpacf(unsigned int opcode, unsigned long func,
				unsigned int r1, unsigned int r2,
				unsigned int r3)
{
	register unsigned long gr0 asm("0") = func;
	cpacf_mask_t mask;
	register unsigned long gr1 asm("1") = (unsigned long)&mask;

	asm volatile(".insn rrf,%[opc] << 16,%[r1],%[r2],%[r3],0\n"
		     : : "d" (gr0), "d" (gr1), [opc] "i" (opcode),
		         [r1] "i" (r1), [r2] "i" (r2), [r3] "i" (r3));
}

static inline void __test_cpacf_r1_odd(unsigned int opcode)
{
	report_prefix_push("r1 odd");
	expect_pgm_int();
	__test_cpacf(opcode, 0, 1, 4, 6);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_r1_null(unsigned int opcode)
{
	report_prefix_push("r1 null");
	expect_pgm_int();
	__test_cpacf(opcode, 0, 0, 4, 6);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_r2_odd(unsigned int opcode)
{
	report_prefix_push("r2 odd");
	expect_pgm_int();
	__test_cpacf(opcode, 0, 2, 3, 6);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_r2_null(unsigned int opcode)
{
	report_prefix_push("r2 null");
	expect_pgm_int();
	__test_cpacf(opcode, 0, 2, 0, 6);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_r3_odd(unsigned int opcode)
{
	report_prefix_push("r3 odd");
	expect_pgm_int();
	__test_cpacf(opcode, 0, 2, 4, 5);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_r3_null(unsigned int opcode)
{
	report_prefix_push("r3 null");
	expect_pgm_int();
	__test_cpacf(opcode, 0, 2, 4, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_mod_bit(unsigned int opcode)
{
	report_prefix_push("mod bit");
	expect_pgm_int();
	__test_cpacf(opcode, CPACF_DECRYPT, 2, 4, 6);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_invalid_func(unsigned int opcode)
{
	report_prefix_push("invalid subfunction");
	expect_pgm_int();
	/* 127 is unassigned for now. We don't simply use any, as HW
	 * might simply mask valid codes in query but they might still work */
	if (cpacf_query_func(opcode, 127)) {
		report_skip("127 not invalid");
	} else {
		__test_cpacf(opcode, 127, 2, 4, 6);
	}
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static inline void __test_cpacf_invalid_parm(unsigned int opcode)
{
	report_prefix_push("invalid parm address");
	expect_pgm_int();
	__cpacf_query(opcode, (void *) -1);
	check_pgm_int_code(PGM_INT_CODE_ADDRESSING);
	report_prefix_pop();
}

static inline void __test_cpacf_protected_parm(unsigned int opcode)
{
	report_prefix_push("protected parm address");
	expect_pgm_int();
	low_prot_enable();
	__cpacf_query(opcode, (void *) 8);
	low_prot_disable();
	check_pgm_int_code(PGM_INT_CODE_PROTECTION);
	report_prefix_pop();
}

static inline void __test_basic_cpacf_opcode(unsigned int opcode)
{
	bool mod_bit_allowed = false;

	if (!__cpacf_check_opcode(opcode)) {
		report_skip("not available");
		return;
	}
	report("query indicated in query", cpacf_query_func(opcode, 0));

	switch (opcode) {
	case CPACF_KMCTR:
		__test_cpacf_r3_odd(opcode);
		__test_cpacf_r3_null(opcode);
		/* FALL THROUGH */
	case CPACF_PRNO:
	case CPACF_KMF:
	case CPACF_KMC:
	case CPACF_KMO:
	case CPACF_KM:
		__test_cpacf_r1_odd(opcode);
		__test_cpacf_r1_null(opcode);
		mod_bit_allowed = true;
		/* FALL THROUGH */
	case CPACF_KMAC:
	case CPACF_KIMD:
	case CPACF_KLMD:
		__test_cpacf_r2_odd(opcode);
		__test_cpacf_r2_null(opcode);
	        break;
	}
	if (!mod_bit_allowed)
		__test_cpacf_mod_bit(opcode);
	__test_cpacf_invalid_func(opcode);
	__test_cpacf_invalid_parm(opcode);
	__test_cpacf_protected_parm(opcode);
}

/* COMPUTE MESSAGE AUTHENTICATION CODE */
static void test_kmac(void)
{
	__test_basic_cpacf_opcode(CPACF_KMAC);
}

/* CIPHER MESSAGE */
static void test_km(void)
{
	__test_basic_cpacf_opcode(CPACF_KM);
}
/* CIPHER MESSAGE WITH CHAINING */
static void test_kmc(void)
{
	__test_basic_cpacf_opcode(CPACF_KMC);
}

/* COMPUTE INTERMEDIATE MESSAGE DIGEST */
static void test_kimd(void)
{
	__test_basic_cpacf_opcode(CPACF_KIMD);
}

/* COMPUTE LAST MESSAGE DIGEST */
static void test_klmd(void)
{
	__test_basic_cpacf_opcode(CPACF_KLMD);
}

/* PERFORM CRYPTOGRAPHIC KEY MANAGEMENT OPERATION */
static void test_pckmo(void)
{
	__test_basic_cpacf_opcode(CPACF_PCKMO);
}

/* CIPHER MESSAGE WITH CIPHER FEEDBACK */
static void test_kmf(void)
{
	__test_basic_cpacf_opcode(CPACF_KMF);
}

/* PERFORM CRYPTOGRAPHIC KEY MANAGEMENT OPERATION */
static void test_kmo(void)
{
	__test_basic_cpacf_opcode(CPACF_KMO);
}

/* PERFORM CRYPTOGRAPHIC COMPUTATION */
static void test_pcc(void)
{
	__test_basic_cpacf_opcode(CPACF_PCC);
}

/* CIPHER MESSAGE WITH COUNTER */
static void test_kmctr(void)
{
	__test_basic_cpacf_opcode(CPACF_KMCTR);
}

/* PERFORM RANDOM NUMBER OPERATION (formerly PPNO) */
static void test_prno(void)
{
	__test_basic_cpacf_opcode(CPACF_PRNO);
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "spm/ipm", test_spm_ipm },
	{ "kmac", test_kmac },
	{ "km", test_km },
	{ "kmc", test_kmc },
	{ "kimd", test_kimd },
	{ "klmd", test_klmd },
	{ "pckmo", test_pckmo },
	{ "kmf", test_kmf },
	{ "kmo", test_kmo },
	{ "pcc", test_pcc },
	{ "kmctr", test_kmctr },
	{ "prno", test_prno },
	{ NULL, NULL }
};

int main(int argc, char**argv)
{
	int i;

	report_prefix_push("emulator");
	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}
	report_prefix_pop();

	return report_summary();
}
