/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CMM migration tests (ESSA)
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */

#include <libcflat.h>
#include <migrate.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm/cmm.h>
#include <bitops.h>

#define NUM_PAGES 128
static uint8_t pagebuf[NUM_PAGES][PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static void test_migration(void)
{
	int i, state_mask, actual_state;
	/*
	 * Maps ESSA actions to states the page is allowed to be in after the
	 * respective action was executed.
	 */
	int allowed_essa_state_masks[4] = {
		BIT(ESSA_USAGE_STABLE),					/* ESSA_SET_STABLE */
		BIT(ESSA_USAGE_UNUSED),					/* ESSA_SET_UNUSED */
		BIT(ESSA_USAGE_VOLATILE),				/* ESSA_SET_VOLATILE */
		BIT(ESSA_USAGE_VOLATILE) | BIT(ESSA_USAGE_POT_VOLATILE) /* ESSA_SET_POT_VOLATILE */
	};

	assert(NUM_PAGES % 4 == 0);
	for (i = 0; i < NUM_PAGES; i += 4) {
		essa(ESSA_SET_STABLE, (unsigned long)pagebuf[i]);
		essa(ESSA_SET_UNUSED, (unsigned long)pagebuf[i + 1]);
		essa(ESSA_SET_VOLATILE, (unsigned long)pagebuf[i + 2]);
		essa(ESSA_SET_POT_VOLATILE, (unsigned long)pagebuf[i + 3]);
	}

	migrate_once();

	for (i = 0; i < NUM_PAGES; i++) {
		actual_state = essa(ESSA_GET_STATE, (unsigned long)pagebuf[i]);
		/* extract the usage state in bits 60 and 61 */
		actual_state = (actual_state >> 2) & 0x3;
		state_mask = allowed_essa_state_masks[i % ARRAY_SIZE(allowed_essa_state_masks)];
		report(BIT(actual_state) & state_mask, "page %d state: expected_mask=0x%x actual_mask=0x%lx", i, state_mask, BIT(actual_state));
	}
}

int main(void)
{
	report_prefix_push("migration-cmm");

	if (!check_essa_available())
		report_skip("ESSA is not available");
	else
		test_migration();

	migrate_once();

	report_prefix_pop();
	return report_summary();
}
