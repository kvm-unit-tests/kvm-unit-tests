/*
 * Test the known dependencies for facilities
 *
 * Copyright 2019 IBM Corp.
 *
 * Authors:
 *    Christian Borntraeger <borntraeger@de.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <asm/facility.h>
#include <vm.h>

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

	report_prefix_pop();
	return report_summary();
}
