/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Test the known dependencies for facilities
 *
 * Copyright 2019, 2021 IBM Corp.
 *
 * Authors:
 *    Christian Borntraeger <borntraeger@de.ibm.com>
 *    Janosch Frank <frankja@linux.ibm.com>
 */

#include <asm/facility.h>
#include <vm.h>
#include <sclp.h>
#include <uv.h>
#include <asm/uv.h>

static void test_sclp_missing_sief2_implications(void)
{
	/* Virtualization related facilities */
	report(!sclp_facilities.has_64bscao, "!64bscao");
	report(!sclp_facilities.has_pfmfi, "!pfmfi");
	report(!sclp_facilities.has_gsls, "!gsls");
	report(!sclp_facilities.has_cmma, "!cmma");
	report(!sclp_facilities.has_esca, "!esca");
	report(!sclp_facilities.has_kss, "!kss");
	report(!sclp_facilities.has_ibs, "!ibs");

	/* Virtualization related facilities reported via CPU entries */
	report(!sclp_facilities.has_sigpif, "!sigpif");
	report(!sclp_facilities.has_sief2, "!sief2");
	report(!sclp_facilities.has_skeyi, "!skeyi");
	report(!sclp_facilities.has_siif, "!siif");
	report(!sclp_facilities.has_cei, "!cei");
	report(!sclp_facilities.has_ib, "!ib");
}

static void test_sclp_features_fmt4(void)
{
	/*
	 * STFLE facilities are handled by the Ultravisor but SCLP
	 * facilities are advertised by the hypervisor.
	 */
	report_prefix_push("PV guest implies");

	/* General facilities */
	report(!sclp_facilities.has_diag318, "!diag318");

	/*
	 * Virtualization related facilities, all of which are
	 * unavailable because there's no virtualization support in a
	 * protected guest.
	 */
	test_sclp_missing_sief2_implications();

	report_prefix_pop();
}

static void test_sclp_features_fmt2(void)
{
	if (sclp_facilities.has_sief2)
		return;

	report_prefix_push("!sief2 implies");
	test_sclp_missing_sief2_implications();
	report_prefix_pop();
}

static void test_sclp_features(void)
{
	report_prefix_push("sclp");

	if (uv_os_is_guest())
		test_sclp_features_fmt4();
	else
		test_sclp_features_fmt2();

	report_prefix_pop();
}

static struct {
	int facility;
	int implied;
	bool expected_tcg_fail;
} dep[] = {
	/* from SA22-7832-11 4-98 facility indications */
	{   4,   3 },
	{   5,   3 },
	{   5,   4 },
	{  19,  18 },
	{  37,  42, true },  /* TCG does not have DFP and won't get it soon */
	{  43,  42 },
	{  73,  49 },
	{ 134, 129 },
	{ 135, 129 },
	{ 139,  25 },
	{ 139,  28 },
	{ 146,  76 },
	/* indirectly documented in description */
	{  78,   8 },  /* EDAT */
	/* new dependencies from gen15 */
	{  61,  45 },
	{ 148, 129 },
	{ 148, 135 },
	{ 152, 129 },
	{ 152, 134 },
	{ 155,  76 },
	{ 155,  77 },
};

int main(void)
{
	int i;

	report_prefix_push("cpumodel");

	report_prefix_push("dependency");
	for (i = 0; i < ARRAY_SIZE(dep); i++) {
		if (test_facility(dep[i].facility)) {
			report_xfail(dep[i].expected_tcg_fail && vm_is_tcg(),
				     test_facility(dep[i].implied),
				     "%d implies %d",
				     dep[i].facility, dep[i].implied);
		} else {
			report_skip("facility %d not present", dep[i].facility);
		}
	}
	report_prefix_pop();

	test_sclp_features();

	report_prefix_pop();
	return report_summary();
}
