/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright IBM Corp. 2023
 *
 * SIE with STLFE interpretive execution facilities test.
 */
#include <libcflat.h>
#include <stdlib.h>
#include <asm/facility.h>
#include <asm/time.h>
#include <snippet.h>
#include <snippet-exit.h>
#include <alloc_page.h>
#include <sclp.h>
#include <rand.h>

static struct vm vm;
static uint64_t (*fac)[PAGE_SIZE / sizeof(uint64_t)];
static prng_state prng_s;

static void setup_guest(void)
{
	extern const char SNIPPET_NAME_START(c, stfle)[];
	extern const char SNIPPET_NAME_END(c, stfle)[];

	setup_vm();
	fac = alloc_pages_flags(0, AREA_DMA31);

	snippet_setup_guest(&vm, false);
	snippet_init(&vm, SNIPPET_NAME_START(c, stfle),
		     SNIPPET_LEN(c, stfle), SNIPPET_UNPACK_OFF);
}

struct guest_stfle_res {
	uint16_t len;
	unsigned char *mem;
};

static struct guest_stfle_res run_guest(void)
{
	struct guest_stfle_res res;
	uint64_t guest_stfle_addr;
	uint64_t reg;

	reset_guest(&vm);
	sie(&vm);
	assert(snippet_is_force_exit_value(&vm));
	guest_stfle_addr = snippet_get_force_exit_value(&vm);
	res.mem = &vm.guest_mem[guest_stfle_addr];
	memcpy(&reg, res.mem, sizeof(reg));
	res.len = (reg & 0xff) + 1;
	res.mem += sizeof(reg);
	return res;
}

static void test_stfle_format_0(void)
{
	struct guest_stfle_res res;

	for (int j = 0; j < stfle_size(); j++)
		WRITE_ONCE((*fac)[j], prng64(&prng_s));
	vm.sblk->fac = (uint32_t)(uint64_t)fac;
	res = run_guest();
	report(res.len == stfle_size(), "stfle len correct");
	report(!memcmp(*fac, res.mem, res.len * sizeof(uint64_t)),
	       "Guest facility list as specified");
}

static void test_stfle_format_2(void)
{
	const int max_stfle_len = 8;
	int guest_max_stfle_len = 0;
	struct guest_stfle_res res;
	bool saturated = false;

	for (int i = 1; i <= max_stfle_len; i++) {
		report_prefix_pushf("max STFLE len %d", i);

		WRITE_ONCE((*fac)[0], i - 1);
		for (int j = 0; j < i; j++)
			WRITE_ONCE((*fac)[j + 1], prng64(&prng_s));
		vm.sblk->fac = (uint32_t)(uint64_t)fac | 2;
		res = run_guest();
		/* len increases up to maximum (machine specific) */
		if (res.len < i)
			saturated = true;
		if (saturated) {
			report(res.len == guest_max_stfle_len, "stfle len correct");
		} else {
			report(res.len == i, "stfle len correct");
			guest_max_stfle_len = i;
		}
		report(!memcmp(&(*fac)[1], res.mem, guest_max_stfle_len * sizeof(uint64_t)),
		       "Guest facility list as specified");

		report_prefix_pop();
	}
}

static void test_no_stfle_format(int format)
{
	report_prefix_pushf("no-stfle");
	reset_guest(&vm);
	vm.sblk->fac = (uint32_t)(uint64_t)fac | format;
	sie_expect_validity(&vm);
	sie(&vm);
	sie_check_optional_validity(&vm, 0x1330);
	report_prefix_pop();
}

struct args {
	uint64_t seed;
};

static bool parse_uint64_t(const char *arg, uint64_t *out)
{
	char *end;
	uint64_t num;

	if (arg[0] == '\0')
		return false;
	num = strtoul(arg, &end, 0);
	if (end[0] != '\0')
		return false;
	*out = num;
	return true;
}

static struct args parse_args(int argc, char **argv)
{
	struct args args;
	const char *flag;
	unsigned int i;
	uint64_t arg;
	bool has_arg;

	stck(&args.seed);

	for (i = 1; i < argc; i++) {
		if (i + 1 < argc)
			has_arg = parse_uint64_t(argv[i + 1], &arg);
		else
			has_arg = false;

		flag = "--seed";
		if (!strcmp(flag, argv[i])) {
			if (!has_arg)
				report_abort("%s needs an uint64_t parameter", flag);
			args.seed = arg;
			++i;
			continue;
		}
		report_abort("Unsupported parameter '%s'",
			     argv[i]);
	}

	return args;
}

int main(int argc, char **argv)
{
	struct args args = parse_args(argc, argv);

	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto out;
	}
	if (!test_facility(7)) {
		report_skip("STFLE facility not available");
		goto out;
	}

	report_info("PRNG seed: 0x%lx", args.seed);
	prng_s = prng_init(args.seed);
	setup_guest();

	report_prefix_pushf("format-0");
	test_stfle_format_0();
	report_prefix_pop();

	report_prefix_pushf("format-1");
	if (!sclp_facilities.has_astfleie1)
		test_no_stfle_format(1);
	report_prefix_pop();

	report_prefix_pushf("format-2");
	if (!sclp_facilities.has_astfleie2) {
		test_no_stfle_format(2);
		report_skip("alternate STFLE interpretive-execution facility 2 not available");
	} else {
		test_stfle_format_2();
	}
	report_prefix_pop();

	report_prefix_pushf("format-3");
	test_no_stfle_format(3);
	report_prefix_pop();

	snippet_destroy_guest(&vm);
out:
	return report_summary();
}
