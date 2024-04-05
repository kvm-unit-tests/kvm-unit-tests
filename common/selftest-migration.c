// SPDX-License-Identifier: GPL-2.0-only
/*
 * Machine independent migration tests
 *
 * This is just a very simple test that is intended to stress the migration
 * support in the test harness. This could be expanded to test more guest
 * library code, but architecture-specific tests should be used to test
 * migration of tricky machine state.
 */
#include <libcflat.h>
#include <migrate.h>
#include <asm/time.h>

#define NR_MIGRATIONS 5

int main(int argc, char **argv)
{
	report_prefix_push("migration harness");

	if (argc > 1 && !strcmp(argv[1], "skip")) {
		migrate_skip();
		report(true, "migration skipping");
	} else {
		int i;

		for (i = 0; i < NR_MIGRATIONS; i++)
			migrate_quiet();
		report(true, "cooperative migration");

		migrate_begin_continuous();
		mdelay(1000);
		migrate_end_continuous();
		mdelay(500);
		migrate_begin_continuous();
		mdelay(1000);
		migrate_end_continuous();
		report(true, "continuous migration");
	}

	report_prefix_pop();

	return report_summary();
}
