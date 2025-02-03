/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Snippet used by the sie-dat.c test to verify paging without MSO/MSL
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <asm-generic/page.h>
#include <asm/mem.h>
#include <snippet-exit.h>
#include "sie-dat.h"

static uint8_t test_pages[GUEST_TEST_PAGE_COUNT * PAGE_SIZE] __attribute__((__aligned__(PAGE_SIZE)));

int main(void)
{
	uint8_t *invalid_ptr;

	memset(test_pages, 0, sizeof(test_pages));
	/* tell the host the page's physical address (we're running DAT off) */
	force_exit_value((uint64_t)test_pages);

	/* write some value to the page so the host can verify it */
	for (size_t i = 0; i < GUEST_TEST_PAGE_COUNT; i++)
		test_pages[i * PAGE_SIZE] = 42 + i;

	/* indicate we've written all pages */
	force_exit();

	/* the first unmapped address */
	invalid_ptr = OPAQUE_PTR(GUEST_TOTAL_PAGE_COUNT * PAGE_SIZE);
	*invalid_ptr = 42;

	/* indicate we've written the non-allowed page (should never get here) */
	force_exit();

	return 0;
}
