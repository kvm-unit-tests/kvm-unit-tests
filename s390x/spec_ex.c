// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright IBM Corp. 2021, 2022
 *
 * Specification exception test.
 * Tests that specification exceptions occur when expected.
 * This includes specification exceptions occurring during transactional execution
 * as these result in another interruption code (the transactional-execution-aborted
 * bit is set).
 *
 * Can be extended by adding triggers to spec_ex_triggers, see comments below.
 */
#include <stdlib.h>
#include <htmintrin.h>
#include <libcflat.h>
#include <bitops.h>
#include <asm/barrier.h>
#include <asm/interrupt.h>
#include <asm/facility.h>

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

static void clear_invalid_psw(void)
{
	expected_psw = PSW(0, 0);
	invalid_psw_expected = false;
}

static int check_invalid_psw(void)
{
	/* Since the fixup sets this to false we check for false here. */
	if (!invalid_psw_expected) {
		/*
		 * Early exception recognition: pgm_int_id == 0.
		 * Late exception recognition: psw address has been
		 *	incremented by pgm_int_id (unpredictable value)
		 */
		if (expected_psw.mask == invalid_psw.mask &&
		    expected_psw.addr == invalid_psw.addr - lowcore.pgm_int_id)
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
	struct psw invalid = PSW(BIT(63 - 12), 0x00000000deadbeee);

	expect_invalid_psw(invalid);
	load_psw(invalid);
	return check_invalid_psw();
}

extern char misaligned_code_pre[];
asm (  ".balign	2\n"
"misaligned_code_pre:\n"
"	. = . + 1\n"
"	larl	%r0,0\n"
"	br	%r1\n"
);

static int psw_odd_address(void)
{
	struct psw odd = PSW_WITH_CUR_MASK(((uint64_t)&misaligned_code_pre) + 1);
	uint64_t executed_addr;

	expect_invalid_psw(odd);
	fixup_psw.mask = extract_psw_mask();
	asm volatile ( "xgr	%%r0,%%r0\n"
		"	larl	%%r1,0f\n"
		"	stg	%%r1,%[fixup_addr]\n"
		"	lpswe	%[odd_psw]\n"
		"0:	lgr	%[executed_addr],%%r0\n"
	: [fixup_addr] "=&T" (fixup_psw.addr),
	  [executed_addr] "=d" (executed_addr)
	: [odd_psw] "Q" (odd)
	: "cc", "%r0", "%r1", "memory" /* Compiler barrier like in load_psw */
	);

	if (!executed_addr) {
		return check_invalid_psw();
	} else {
		assert(executed_addr == odd.addr);
		clear_invalid_psw();
		report_fail("did not execute unaligned instructions");
		return 1;
	}
}

/* A short PSW needs to have bit 12 set to be valid. */
static int short_psw_bit_12_is_0(void)
{
	struct psw invalid = PSW(BIT(63 - 12), 0x00000000deadbeee);
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

static int odd_ex_target(void)
{
	uint64_t pre_target_addr;
	int to = 0, from = 0x0dd;

	asm volatile ( ".pushsection .text.ex_odd\n"
		"	.balign	2\n"
		"pre_odd_ex_target%=:\n"
		"	. = . + 1\n"
		"	lr	%[to],%[from]\n"
		"	.popsection\n"

		"	larl	%[pre_target_addr],pre_odd_ex_target%=\n"
		"	ex	0,1(%[pre_target_addr])\n"
		: [pre_target_addr] "=&a" (pre_target_addr),
		  [to] "+d" (to)
		: [from] "d" (from)
	);

	assert((pre_target_addr + 1) & 1);
	report(to != from, "did not perform ex with odd target");
	return 0;
}

static int bad_alignment_lqp(void)
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

static int bad_alignment_lrl(void)
{
	uint64_t r;

	asm volatile ( ".pushsection .rodata\n"
		"	.balign	4\n"
		"	. = . + 2\n"
		"0:	.fill	4\n"
		"	.popsection\n"

		"	lrl	%0,0b\n"
		: "=d" (r)
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
 * If a trigger is transactable it will also be executed during a transaction.
 */
struct spec_ex_trigger {
	const char *name;
	int (*func)(void);
	bool transactable;
	void (*fixup)(struct stack_frame_int *stack);
};

/* List of all tests to execute */
static const struct spec_ex_trigger spec_ex_triggers[] = {
	{ "psw_bit_12_is_1", &psw_bit_12_is_1, false, &fixup_invalid_psw },
	{ "short_psw_bit_12_is_0", &short_psw_bit_12_is_0, false, &fixup_invalid_psw },
	{ "psw_odd_address", &psw_odd_address, false, &fixup_invalid_psw },
	{ "odd_ex_target", &odd_ex_target, true, NULL },
	{ "bad_alignment_lqp", &bad_alignment_lqp, true, NULL },
	{ "bad_alignment_lrl", &bad_alignment_lrl, true, NULL },
	{ "not_even", &not_even, true, NULL },
	{ NULL, NULL, false, NULL },
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

#define TRANSACTION_COMPLETED 4
#define TRANSACTION_MAX_RETRIES 5

/*
 * NULL must not be passed to __builtin_tbegin via variable, only constant,
 * forbid diagnose from being NULL at all to keep things simple
 */
static int __attribute__((nonnull))
with_transaction(int (*trigger)(void), struct __htm_tdb *diagnose)
{
	int cc;

	cc = __builtin_tbegin(diagnose);
	/*
	 * Everything between tbegin and tend is part of the transaction,
	 * which either completes in its entirety or does not have any effect.
	 * If the transaction fails, execution is reset to this point with another
	 * condition code indicating why the transaction failed.
	 */
	if (cc == _HTM_TBEGIN_STARTED) {
		/*
		 * return code is meaningless: transaction needs to complete
		 * in order to return and completion indicates a test failure
		 */
		trigger();
		__builtin_tend();
		return TRANSACTION_COMPLETED;
	} else {
		return cc;
	}
}

static int retry_transaction(const struct spec_ex_trigger *trigger, unsigned int max_retries,
			     struct __htm_tdb *tdb, uint16_t expected_pgm)
{
	int trans_result, i;
	uint16_t pgm;

	for (i = 0; i < max_retries; i++) {
		expect_pgm_int();
		trans_result = with_transaction(trigger->func, tdb);
		if (trans_result == _HTM_TBEGIN_TRANSIENT) {
			mb();
			pgm = lowcore.pgm_int_code;
			if (pgm == expected_pgm)
				return 0;
			else if (pgm == 0)
				/*
				 * Transaction failed for unknown reason but not because
				 * of an unexpected program exception. Give it another
				 * go so that hopefully it reaches the triggering instruction.
				 */
				continue;
		}
		return trans_result;
	}
	return TRANSACTION_MAX_RETRIES;
}

struct args {
	uint64_t max_retries;
	bool diagnose;
};

static void test_spec_ex_trans(struct args *args, const struct spec_ex_trigger *trigger)
{
	const uint16_t expected_pgm = PGM_INT_CODE_SPECIFICATION |
				      PGM_INT_CODE_TX_ABORTED_EVENT;
	union {
		struct __htm_tdb tdb;
		uint64_t dwords[sizeof(struct __htm_tdb) / sizeof(uint64_t)];
	} diag;
	unsigned int i;
	int trans_result;

	if (!test_facility(73)) {
		report_skip("transactional-execution facility not installed");
		return;
	}
	ctl_set_bit(0, CTL0_TRANSACT_EX_CTL); /* enable transactional-exec */

	register_pgm_cleanup_func(trigger->fixup);
	trans_result = retry_transaction(trigger, args->max_retries, &diag.tdb, expected_pgm);
	register_pgm_cleanup_func(NULL);
	switch (trans_result) {
	case 0:
		report_pass("Program interrupt: expected(%d) == received(%d)",
			    expected_pgm, expected_pgm);
		break;
	case _HTM_TBEGIN_INDETERMINATE:
	case _HTM_TBEGIN_PERSISTENT:
		report_info("transaction failed with cc %d", trans_result);
		report_info("transaction abort code: %llu", diag.tdb.abort_code);
		if (args->diagnose)
			for (i = 0; i < 32; i++)
				report_info("diag+%03d: %016lx", i * 8, diag.dwords[i]);
		break;
	case _HTM_TBEGIN_TRANSIENT:
		report_fail("Program interrupt: expected(%d) == received(%d)",
			    expected_pgm, clear_pgm_int());
		break;
	case TRANSACTION_COMPLETED:
		report_fail("Transaction completed without exception");
		break;
	case TRANSACTION_MAX_RETRIES:
		report_skip("Transaction retried %lu times with transient failures, giving up",
			    args->max_retries);
		break;
	default:
		report_fail("Invalid transaction result");
		break;
	}

	ctl_clear_bit(0, CTL0_TRANSACT_EX_CTL);
}

static bool parse_unsigned(const char *arg, unsigned int *out)
{
	char *end;
	long num;

	if (arg[0] == '\0')
		return false;
	num = strtol(arg, &end, 10);
	if (end[0] != '\0' || num < 0)
		return false;
	*out = num;
	return true;
}

static struct args parse_args(int argc, char **argv)
{
	struct args args = {
		.max_retries = 20,
		.diagnose = false
	};
	unsigned int i, arg;
	bool has_arg;
	const char *flag;

	for (i = 1; i < argc; i++) {
		if (i + 1 < argc)
			has_arg = parse_unsigned(argv[i + 1], &arg);
		else
			has_arg = false;

		flag = "--max-retries";
		if (!strcmp(flag, argv[i])) {
			if (!has_arg)
				report_abort("%s needs a positive parameter", flag);
			args.max_retries = arg;
			++i;
			continue;
		}
		if (!strcmp("--diagnose", argv[i])) {
			args.diagnose = true;
			continue;
		}
		if (!strcmp("--no-diagnose", argv[i])) {
			args.diagnose = false;
			continue;
		}
		report_abort("Unsupported parameter '%s'",
			     argv[i]);
	}

	return args;
}

int main(int argc, char **argv)
{
	unsigned int i;

	struct args args = parse_args(argc, argv);

	report_prefix_push("specification exception");
	for (i = 0; spec_ex_triggers[i].name; i++) {
		report_prefix_push(spec_ex_triggers[i].name);
		test_spec_ex(&spec_ex_triggers[i]);
		report_prefix_pop();
	}
	report_prefix_pop();

	report_prefix_push("specification exception during transaction");
	for (i = 0; spec_ex_triggers[i].name; i++) {
		if (spec_ex_triggers[i].transactable) {
			report_prefix_push(spec_ex_triggers[i].name);
			test_spec_ex_trans(&args, &spec_ex_triggers[i]);
			report_prefix_pop();
		}
	}
	report_prefix_pop();

	return report_summary();
}
