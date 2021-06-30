// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright IBM Corp. 2021, 2022
 *
 * Specification exception test.
 * Tests that specification exceptions occur when expected.
 *
 * Can be extended by adding triggers to spec_ex_triggers, see comments below.
 */
#include <stdlib.h>
#include <libcflat.h>
#include <bitops.h>
#include <asm/interrupt.h>

/* toggled to signal occurrence of invalid psw fixup */
static bool invalid_psw_expected;
static struct psw expected_psw;
static struct psw invalid_psw;
static struct psw fixup_psw;

/*
 * The standard program exception handler cannot deal with invalid old PSWs,
 * especially not invalid instruction addresses, as in that case one cannot
 * find the instruction following the faulting one from the old PSW.
 * The PSW to return to is set by load_psw.
 */
static void fixup_invalid_psw(struct stack_frame_int *stack)
{
	assert_msg(invalid_psw_expected,
		   "Unexpected invalid PSW during program interrupt fixup: %#lx %#lx",
		   lowcore.pgm_old_psw.mask, lowcore.pgm_old_psw.addr);
	/* signal occurrence of invalid psw fixup */
	invalid_psw_expected = false;
	invalid_psw = lowcore.pgm_old_psw;
	lowcore.pgm_old_psw = fixup_psw;
}

/*
 * Load possibly invalid psw, but setup fixup_psw before,
 * so that fixup_invalid_psw() can bring us back onto the right track.
 * Also acts as compiler barrier, -> none required in expect/check_invalid_psw
 */
static void load_psw(struct psw psw)
{
	uint64_t scratch;

	/*
	 * The fixup psw is the current psw with the instruction address replaced
	 * by the address of the nop following the instruction loading the new psw.
	 */
	fixup_psw.mask = extract_psw_mask();
	asm volatile ( "larl	%[scratch],0f\n"
		"	stg	%[scratch],%[fixup_addr]\n"
		"	lpswe	%[psw]\n"
		"0:	nop\n"
		: [scratch] "=&d" (scratch),
		  [fixup_addr] "=&T" (fixup_psw.addr)
		: [psw] "Q" (psw)
		: "cc", "memory"
	);
}

static void load_short_psw(struct short_psw psw)
{
	uint64_t scratch;

	fixup_psw.mask = extract_psw_mask();
	asm volatile ( "larl	%[scratch],0f\n"
		"	stg	%[scratch],%[fixup_addr]\n"
		"	lpsw	%[psw]\n"
		"0:	nop\n"
		: [scratch] "=&d" (scratch),
		  [fixup_addr] "=&T" (fixup_psw.addr)
		: [psw] "Q" (psw)
		: "cc", "memory"
	);
}

static void expect_invalid_psw(struct psw psw)
{
	expected_psw = psw;
	invalid_psw_expected = true;
}

static int check_invalid_psw(void)
{
	/* Since the fixup sets this to false we check for false here. */
	if (!invalid_psw_expected) {
		if (expected_psw.mask == invalid_psw.mask &&
		    expected_psw.addr == invalid_psw.addr)
			return 0;
		report_fail("Wrong invalid PSW");
	} else {
		report_fail("Expected exception due to invalid PSW");
	}
	return 1;
}

/* For normal PSWs bit 12 has to be 0 to be a valid PSW*/
static int psw_bit_12_is_1(void)
{
	struct psw invalid = {
		.mask = BIT(63 - 12),
		.addr = 0x00000000deadbeee
	};

	expect_invalid_psw(invalid);
	load_psw(invalid);
	return check_invalid_psw();
}

/* A short PSW needs to have bit 12 set to be valid. */
static int short_psw_bit_12_is_0(void)
{
	struct psw invalid = {
		.mask = BIT(63 - 12),
		.addr = 0x00000000deadbeee
	};
	struct short_psw short_invalid = {
		.mask = 0x0,
		.addr = 0xdeadbeee
	};

	expect_invalid_psw(invalid);
	load_short_psw(short_invalid);
	/*
	 * lpsw may optionally check bit 12 before loading the new psw
	 * -> cannot check the expected invalid psw like with lpswe
	 */
	return 0;
}

static int bad_alignment(void)
{
	uint32_t words[5] __attribute__((aligned(16)));
	uint32_t (*bad_aligned)[4] = (uint32_t (*)[4])&words[1];

	/* LOAD PAIR FROM QUADWORD (LPQ) requires quadword alignment */
	asm volatile ("lpq %%r6,%[bad]"
		      : : [bad] "T" (*bad_aligned)
		      : "%r6", "%r7"
	);
	return 0;
}

static int not_even(void)
{
	uint64_t quad[2] __attribute__((aligned(16))) = {0};

	asm volatile (".insn	rxy,0xe3000000008f,%%r7,%[quad]" /* lpq %%r7,%[quad] */
		      : : [quad] "T" (quad)
		      : "%r7", "%r8"
	);
	return 0;
}

/*
 * Harness for specification exception testing.
 * func only triggers exception, reporting is taken care of automatically.
 */
struct spec_ex_trigger {
	const char *name;
	int (*func)(void);
	void (*fixup)(struct stack_frame_int *stack);
};

/* List of all tests to execute */
static const struct spec_ex_trigger spec_ex_triggers[] = {
	{ "psw_bit_12_is_1", &psw_bit_12_is_1, &fixup_invalid_psw },
	{ "short_psw_bit_12_is_0", &short_psw_bit_12_is_0, &fixup_invalid_psw },
	{ "bad_alignment", &bad_alignment, NULL },
	{ "not_even", &not_even, NULL },
	{ NULL, NULL, NULL },
};

static void test_spec_ex(const struct spec_ex_trigger *trigger)
{
	int rc;

	expect_pgm_int();
	register_pgm_cleanup_func(trigger->fixup);
	rc = trigger->func();
	register_pgm_cleanup_func(NULL);
	/* test failed, nothing to be done, reporting responsibility of trigger */
	if (rc)
		return;
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
}

int main(int argc, char **argv)
{
	unsigned int i;

	report_prefix_push("specification exception");
	for (i = 0; spec_ex_triggers[i].name; i++) {
		report_prefix_push(spec_ex_triggers[i].name);
		test_spec_ex(&spec_ex_triggers[i]);
		report_prefix_pop();
	}
	report_prefix_pop();

	return report_summary();
}
