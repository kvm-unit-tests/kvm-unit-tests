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

static void gen_report(struct sbiret *ret, long expected)
{
	report(!ret->error, "no sbi.error");
	report(ret->value == expected, "expected sbi.value");
}

static void check_base(void)
{
	struct sbiret ret;
	long expected;

	report_prefix_push("base");

	report_prefix_push("mvendorid");
	if (env_or_skip("MVENDORID")) {
		expected = strtol(getenv("MVENDORID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MVENDORID, 0);
		gen_report(&ret, expected);
	}
	report_prefix_pop();

	report_prefix_push("probe_ext");
	expected = getenv("PROBE_EXT") ? strtol(getenv("PROBE_EXT"), NULL, 0) : 1;
	ret = __base_sbi_ecall(SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE);
	gen_report(&ret, expected);
	report_prefix_pop();

	report_prefix_push("marchid");
	if (env_or_skip("MARCHID")) {
		expected = strtol(getenv("MARCHID"), NULL, 0);
		ret = __base_sbi_ecall(SBI_EXT_BASE_GET_MARCHID, 0);
		gen_report(&ret, expected);
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
