/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Migration-related functions
 *
 * Copyright IBM Corp. 2022
 * Author: Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include "migrate.h"

/*
 * Initiate migration and wait for it to complete.
 */
void migrate(void)
{
	puts("Now migrate the VM, then press a key to continue...\n");
	(void)getchar();
	report_info("Migration complete");
}

/*
 * Like migrate() but suppress output and logs, useful for intensive
 * migration stress testing without polluting logs. Test cases should
 * provide relevant information about migration in failure reports.
 */
void migrate_quiet(void)
{
	puts("Now migrate the VM (quiet)\n");
	(void)getchar();
}

/*
 * Initiate migration and wait for it to complete.
 * If this function is called more than once, it is a no-op.
 */
void migrate_once(void)
{
	static bool migrated;

	if (migrated)
		return;

	migrated = true;
	migrate();
}
