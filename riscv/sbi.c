// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <stdlib.h>
#include <asm/sbi.h>

static void help(void)
{
	puts("Test SBI\n");
	puts("An environ must be provided where expected values are given.\n");
}

static struct sbiret __base_sbi_ecall(int fid, unsigned long arg0)
{
	return sbi_ecall(SBI_EXT_BASE, fid, arg0, 0, 0, 0, 0, 0);
}

static bool env_or_skip(const char *env)
{
	if (!getenv(env)) {
		report_skip("missing %s environment variable", env);
		return false;
	}

	return true;
}

static void gen_report(struct sbiret *ret,
		       long expected_error, long expected_value)
{
	bool check_error = ret->error == expected_error;
	bool check_value = ret->value == expected_value;

	if (!check_error || !check_value)
		report_info("expected (error: %ld, value: %ld), received: (error: %ld, value %ld)",
			    expected_error, expected_value, ret->error, ret->value);

	report(check_error, "expected sbi.error");
	report(check_value, "expected sbi.value");
}

static void check_base(void)
{
	struct sbiret ret;
	long expected;

	report_prefix_push("base");

	ret = __base_sbi_ecall(SBI_EXT_BASE_GET_SPEC_VERSION, 0);
	if (ret.error || ret.value < 2) {
		report_skip("SBI spec version 0.2 or higher required");
		return;
	}

	report_prefix_push("spec_version");
	if (env_or_skip("SPEC_VERSION")) {
		expected = strtol(getenv("SPEC_VERSION"), NULL, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("impl_id");
	if (env_or_skip("IMPL_ID")) {
		expected = strtol(getenv("IMPL_ID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_IMP_ID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("impl_version");
	if (env_or_skip("IMPL_VERSION")) {
		expected = strtol(getenv("IMPL_VERSION"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_IMP_VERSION, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("probe_ext");
	expected = getenv("PROBE_EXT") ? strtol(getenv("PROBE_EXT"), NULL, 0) : 1;
	ret = __base_sbi_ecall(SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE);
	gen_report(&ret, 0, expected);
	report_prefix_push("unavailable");
	ret = __base_sbi_ecall(SBI_EXT_BASE_PROBE_EXT, 0xb000000);
	gen_report(&ret, 0, 0);
	report_prefix_pop();
	report_prefix_pop();

	report_prefix_push("mvendorid");
	if (env_or_skip("MVENDORID")) {
		expected = strtol(getenv("MVENDORID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MVENDORID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("marchid");
	if (env_or_skip("MARCHID")) {
		expected = strtol(getenv("MARCHID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MARCHID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_push("mimpid");
	if (env_or_skip("MIMPID")) {
		expected = strtol(getenv("MIMPID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MIMPID, 0);
		gen_report(&ret, 0, expected);
	}
	report_prefix_pop();

	report_prefix_pop();
}

int main(int argc, char **argv)
{

	if (argc > 1 && !strcmp(argv[1], "-h")) {
		help();
		exit(0);
	}

	report_prefix_push("sbi");
	check_base();

	return report_summary();
}
