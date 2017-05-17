/*
 * Test sPAPR hypervisor calls (aka. h-calls)
 *
 * Copyright 2016  Thomas Huth, Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <util.h>
#include <alloc.h>
#include <asm/hcall.h>

#define PAGE_SIZE 4096

#define H_ZERO_PAGE	(1UL << (63-48))
#define H_COPY_PAGE	(1UL << (63-49))

#define mfspr(nr) ({ \
	uint64_t ret; \
	asm volatile("mfspr %0,%1" : "=r"(ret) : "i"(nr)); \
	ret; \
})

#define SPR_SPRG0	0x110

/**
 * Test the H_SET_SPRG0 h-call by setting some values and checking whether
 * the SPRG0 register contains the correct values afterwards
 */
static void test_h_set_sprg0(int argc, char **argv)
{
	uint64_t sprg0, sprg0_orig;
	int rc;

	if (argc > 1)
		report_abort("Unsupported argument: '%s'", argv[1]);

	sprg0_orig = mfspr(SPR_SPRG0);

	rc = hcall(H_SET_SPRG0, 0xcafebabedeadbeefULL);
	sprg0 = mfspr(SPR_SPRG0);
	report("sprg0 = 0xcafebabedeadbeef",
		rc == H_SUCCESS && sprg0 == 0xcafebabedeadbeefULL);

	rc = hcall(H_SET_SPRG0, 0xaaaaaaaa55555555ULL);
	sprg0 = mfspr(SPR_SPRG0);
	report("sprg0 = 0xaaaaaaaa55555555",
		rc == H_SUCCESS && sprg0 == 0xaaaaaaaa55555555ULL);

	rc = hcall(H_SET_SPRG0, sprg0_orig);
	sprg0 = mfspr(SPR_SPRG0);
	report("sprg0 = %#" PRIx64,
		rc == H_SUCCESS && sprg0 == sprg0_orig, sprg0_orig);
}

/**
 * Test the H_PAGE_INIT h-call by using it to clear and to copy a page, and
 * by checking for the correct values in the destination page afterwards
 */
static void test_h_page_init(int argc, char **argv)
{
	u8 *dst, *src;
	int rc;

	if (argc > 1)
		report_abort("Unsupported argument: '%s'", argv[1]);

	dst = memalign(PAGE_SIZE, PAGE_SIZE);
	src = memalign(PAGE_SIZE, PAGE_SIZE);
	if (!dst || !src)
		report_abort("Failed to alloc memory");

	memset(dst, 0xaa, PAGE_SIZE);
	rc = hcall(H_PAGE_INIT, H_ZERO_PAGE, dst, src);
	report("h_zero_page", rc == H_SUCCESS && *(uint64_t*)dst == 0);

	*(uint64_t*)src = 0xbeefc0dedeadcafeULL;
	rc = hcall(H_PAGE_INIT, H_COPY_PAGE, dst, src);
	report("h_copy_page",
		rc == H_SUCCESS && *(uint64_t*)dst == 0xbeefc0dedeadcafeULL);

	*(uint64_t*)src = 0x9abcdef012345678ULL;
	rc = hcall(H_PAGE_INIT, H_COPY_PAGE|H_ZERO_PAGE, dst, src);
	report("h_copy_page+h_zero_page",
		rc == H_SUCCESS &&  *(uint64_t*)dst == 0x9abcdef012345678ULL);

	rc = hcall(H_PAGE_INIT, H_ZERO_PAGE, dst + 0x123, src);
	report("h_zero_page unaligned dst", rc == H_PARAMETER);

	rc = hcall(H_PAGE_INIT, H_COPY_PAGE, dst, src + 0x123);
	report("h_copy_page unaligned src", rc == H_PARAMETER);
}

static int h_random(uint64_t *val)
{
	register uint64_t r3 asm("r3") = H_RANDOM;
	register uint64_t r4 asm("r4");

	asm volatile (" sc 1 "	: "+r"(r3), "=r"(r4) :
				: "r0", "r5", "r6", "r7", "r8", "r9", "r10",
				  "r11", "r12", "xer", "ctr", "cc");
	*val = r4;

	return r3;
}

/**
 * Test H_RANDOM by calling it a couple of times to check whether all bit
 * positions really toggle (there should be no "stuck" bits in the output)
 */
static void test_h_random(int argc, char **argv)
{
	uint64_t rval, val0, val1;
	int rc, i;

	if (argc > 1)
		report_abort("Unsupported argument: '%s'", argv[1]);

	/* H_RANDOM is optional - so check for sane return values first */
	rc = h_random(&rval);
	report_xfail("h-call available", rc == H_FUNCTION, rc == H_SUCCESS);
	if (rc != H_SUCCESS)
		return;

	val0 = 0ULL;
	val1 = ~0ULL;

	i = 100;
	do {
		rc = h_random(&rval);
		if (rc != H_SUCCESS)
			break;
		val0 |= rval;
		val1 &= rval;
	} while (i-- > 0 && (val0 != ~0ULL || val1 != 0ULL));

	report("no stuck bits", rc == H_SUCCESS && val0 == ~0ULL && val1 == 0);
}

struct {
	const char *name;
	void (*func)(int argc, char **argv);
} hctests[] = {
	{ "h_set_sprg0", test_h_set_sprg0 },
	{ "h_page_init", test_h_page_init },
	{ "h_random", test_h_random },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	int all = 0;
	int i;

	report_prefix_push("hypercall");

	if (argc < 2 || (argc == 2 && !strcmp(argv[1], "all")))
		all = 1;

	for (i = 0; hctests[i].name != NULL; i++) {
		report_prefix_push(hctests[i].name);
		if (all || strcmp(argv[1], hctests[i].name) == 0) {
			hctests[i].func(argc-1, &argv[1]);
		}
		report_prefix_pop();
	}

	return report_summary();
}
