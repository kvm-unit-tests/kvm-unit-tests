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

#define NR_MIGRATIONS 30

int main(int argc, char **argv)
{
	report_prefix_push("migration");

	if (argc > 1 && !strcmp(argv[1], "skip")) {
		migrate_skip();
		report(true, "migration skipping");
	} else {
		int i;

		for (i = 0; i < NR_MIGRATIONS; i++)
			migrate_quiet();
		report(true, "simple harness stress");
	}

	report_prefix_pop();

	return report_summary();
}
