/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SET CLOCK migration tests
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */

#include <libcflat.h>
#include <migrate.h>
#include <asm/time.h>

static void test_sck_migration(void)
{
	uint64_t now_before_set = 0, now_after_set = 0, now_after_migration, time_to_set, time_to_advance;
	int cc;

	stckf(&now_before_set);

	/* Advance the clock by a lot more than we might ever need to migrate (600s) */
	time_to_advance = (600ULL * 1000000) << STCK_SHIFT_US;
	time_to_set = now_before_set + time_to_advance;

	cc = sck(&time_to_set);
	report(!cc, "setting clock succeeded");

	/* Check the clock is running after being set */
	cc = stckf(&now_after_set);
	report(!cc, "clock running after set");
	report(now_after_set >= time_to_set, "TOD clock value is larger than what has been set");

	migrate_once();

	cc = stckf(&now_after_migration);
	report(!cc, "clock still set");

	/*
	 * The architectural requirement for the TOD clock is that it doesn't move backwards after
	 * migration. Implementations can just migrate the guest TOD value or do something more
	 * sophisticated (e.g. slowly adjust to the host TOD).
	 */
	report(now_after_migration >= time_to_set, "TOD clock value did not jump backwards");
}

int main(void)
{
	report_prefix_push("migration-sck");

	test_sck_migration();
	report_prefix_pop();
	return report_summary();
}
