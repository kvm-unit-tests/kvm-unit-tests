// SPDX-License-Identifier: GPL-2.0-only
/*
 * Simple memory verification test, used to exercise dirty memory migration.
 */
#include <libcflat.h>
#include <migrate.h>
#include <alloc.h>
#include <asm/page.h>
#include <asm/time.h>

#define NR_PAGES 32
#define SIZE (NR_PAGES * PAGE_SIZE)

static unsigned time_sec = 5;

static void do_getopts(int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "-t") == 0) {
			i++;
			if (i == argc)
				break;
			time_sec = atol(argv[i]);
		}
	}

	printf("running for %d secs\n", time_sec);
}

int main(int argc, char **argv)
{
	void *mem = memalign(PAGE_SIZE, SIZE);
	bool success = true;
	uint64_t ms;
	long i;

	do_getopts(argc, argv);

	report_prefix_push("memory");

	memset(mem, 0, SIZE);

	migrate_begin_continuous();
	ms = get_clock_ms();
	i = 0;
	do {
		int j;

		for (j = 0; j < SIZE; j += PAGE_SIZE) {
			if (*(volatile long *)(mem + j) != i) {
				success = false;
				goto out;
			}
			*(volatile long *)(mem + j) = i + 1;
		}
		i++;
	} while (get_clock_ms() - ms < time_sec * 1000);
out:
	migrate_end_continuous();

	report(success, "memory verification stress test");

	report_prefix_pop();

	return report_summary();
}
