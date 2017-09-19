/*
 * Emulator tests - for s390x CPU instructions that are usually interpreted
 *                  by the hardware
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#include <libcflat.h>

static inline void __test_spm_ipm(uint8_t cc, uint8_t key)
{
	uint64_t in = (cc << 28) | (key << 24);
	uint64_t out = ~0ULL;

	report_prefix_pushf("cc=%d,key=%x", cc, key);

	asm volatile ("spm %1\n"
		      "ipm %0\n"
		      : "+r"(out) : "r"(in) : "cc");

	report("bit 32 and 33 set to zero", !(out & 0xc0000000UL));
	report("bit 0-31, 40-63 unchanged",
		(out & ~0xff000000ULL) == ~0xff000000ULL);
	report("cc and key applied", !((in ^ out) & 0x3f000000UL));

	report_prefix_pop();
}

/* Test the SET PROGRAM PARAMETER and INSERT PROGRAM PARAMETER instruction */
static void test_spm_ipm(void)
{
	__test_spm_ipm(0, 0xf);
	__test_spm_ipm(1, 0x9);
	__test_spm_ipm(2, 0x5);
	__test_spm_ipm(3, 0x3);
	__test_spm_ipm(0, 0);
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "spm/ipm", test_spm_ipm },
	{ NULL, NULL }
};

int main(int argc, char**argv)
{
	int i;

	report_prefix_push("emulator");
	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}
	report_prefix_pop();

	return report_summary();
}
