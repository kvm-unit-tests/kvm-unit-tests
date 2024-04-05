/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Migration-related functions
 *
 * Copyright IBM Corp. 2022
 * Author: Nico Boehr <nrb@linux.ibm.com>
 */

void migrate(void);
void migrate_quiet(void);
void migrate_once(void);

void migrate_skip(void);

void migrate_begin_continuous(void);
void migrate_end_continuous(void);
