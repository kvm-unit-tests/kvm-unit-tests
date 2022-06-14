/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Storage Key migration tests
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */

#include <libcflat.h>
#include <asm/facility.h>
#include <asm/page.h>
#include <asm/mem.h>
#include <asm/interrupt.h>
#include <hardware.h>

#define NUM_PAGES 128
static uint8_t pagebuf[NUM_PAGES][PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static void test_migration(void)
{
	union skey expected_key, actual_key;
	int i, key_to_set, key_mismatches = 0;

	for (i = 0; i < NUM_PAGES; i++) {
		/*
		 * Storage keys are 7 bit, lowest bit is always returned as zero
		 * by iske.
		 * This loop will set all 7 bits which means we set fetch
		 * protection as well as reference and change indication for
		 * some keys.
		 */
		key_to_set = i * 2;
		set_storage_key(pagebuf[i], key_to_set, 1);
	}

	puts("Please migrate me, then press return\n");
	(void)getchar();

	for (i = 0; i < NUM_PAGES; i++) {
		actual_key.val = get_storage_key(pagebuf[i]);
		expected_key.val = i * 2;

		/*
		 * The PoP neither gives a guarantee that the reference bit is
		 * accurate nor that it won't be cleared by hardware. Hence we
		 * don't rely on it and just clear the bits to avoid compare
		 * errors.
		 */
		actual_key.str.rf = 0;
		expected_key.str.rf = 0;

		/* don't log anything when key matches to avoid spamming the log */
		if (actual_key.val != expected_key.val) {
			key_mismatches++;
			report_fail("page %d expected_key=0x%x actual_key=0x%x", i, expected_key.val, actual_key.val);
		}
	}

	report(!key_mismatches, "skeys after migration match");
}

int main(void)
{
	report_prefix_push("migration-skey");
	if (test_facility(169)) {
		report_skip("storage key removal facility is active");

		/*
		 * If we just exit and don't ask migrate_cmd to migrate us, it
		 * will just hang forever. Hence, also ask for migration when we
		 * skip this test altogether.
		 */
		puts("Please migrate me, then press return\n");
		(void)getchar();
	} else {
		test_migration();
	}

	report_prefix_pop();
	return report_summary();
}
