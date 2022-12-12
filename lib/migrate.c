/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Migration-related functions
 *
 * Copyright IBM Corp. 2022
 * Author: Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include "migrate.h"

/* static for now since we only support migrating exactly once per test. */
static void migrate(void)
{
	puts("Now migrate the VM, then press a key to continue...\n");
	(void)getchar();
	report_info("Migration complete");
}

/*
 * Initiate migration and wait for it to complete.
 * If this function is called more than once, it is a no-op.
 * Since migrate_cmd can only migrate exactly once this function can
 * simplify the control flow, especially when skipping tests.
 */
void migrate_once(void)
{
	static bool migrated;

	if (migrated)
		return;

	migrated = true;
	migrate();
}
