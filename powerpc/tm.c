/*
 * Transactional Memory Unit Tests
 *
 * Copyright 2016 Suraj Jitindar Singh, IBM.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/hcall.h>
#include <asm/processor.h>
#include <asm/handlers.h>
#include <asm/smp.h>
#include <asm/setup.h>
#include <devicetree.h>

/* Check "ibm,pa-features" property of a CPU node for the TM flag */
static void cpu_has_tm(int fdtnode, u64 regval __unused, void *ptr)
{
	const struct fdt_property *prop;
	int plen;

	prop = fdt_get_property(dt_fdt(), fdtnode, "ibm,pa-features", &plen);
	if (!prop)	/* No features means TM is also not available */
		return;
	/* Sanity check for the property layout (first two bytes are header) */
	assert(plen >= 8 && prop->data[1] == 0 && prop->data[0] <= plen - 2);

	/*
	 * The "Transactional Memory Category Support" flags are at byte
	 * offset 22 and 23 of the attribute type 0, so when adding the
	 * two bytes for the header, we've got to look at offset 24 for
	 * the TM support bit.
	 */
	if (prop->data[0] >= 24 && (prop->data[24] & 0x80) != 0)
		*(int *)ptr += 1;
}

/* Check whether all CPU nodes have the TM flag */
static bool all_cpus_have_tm(void)
{
	int ret;
	int available = 0;

	ret = dt_for_each_cpu_node(cpu_has_tm, &available);

	return ret == 0 && available == nr_cpus;
}

static int h_cede(void)
{
	register uint64_t r3 asm("r3") = H_CEDE;

	asm volatile ("sc 1" : "+r"(r3) :
			     : "r0", "r4", "r5", "r6", "r7", "r8", "r9",
			       "r10", "r11", "r12", "xer", "ctr", "cc");

	return r3;
}

/*
 * Enable transactional memory
 * Returns:	FALSE - Failure
 *		TRUE - Success
 */
static bool enable_tm(void)
{
	uint64_t msr = 0;

	asm volatile ("mfmsr %[msr]" : [msr] "=r" (msr));

	msr |= (((uint64_t) 1) << 32);

	asm volatile ("mtmsrd %[msr]\n\t"
		      "mfmsr %[msr]" : [msr] "+r" (msr));

	return !!(msr & (((uint64_t) 1) << 32));
}

/*
 * Test H_CEDE call while transactional memory transaction is suspended
 *
 * WARNING: This tests for a known vulnerability in which the host may go down.
 * Probably best not to run this if your host going down is going to cause
 * problems.
 *
 * If the test passes then your kernel probably has the necessary patch.
 * If the test fails then the H_CEDE call was unsuccessful and the
 * vulnerability wasn't tested.
 * If the test hits the vulnerability then it will never complete or report and
 * the qemu process will block indefinitely. RCU stalls will be detected on the
 * cpu and any process scheduled on the lost cpu will also block indefinitely.
 */
static void test_h_cede_tm(int argc, char **argv)
{
	int i;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	handle_exception(0x900, &dec_except_handler, NULL);

	if (!start_all_cpus(halt, 0))
		report_abort("Failed to start secondary cpus");

	if (!enable_tm())
		report_abort("Failed to enable tm");

	/*
	 * Begin a transaction and guarantee we are in the suspend state
	 * before continuing
	 */
	asm volatile ("1: .long 0x7c00051d\n\t"	/* tbegin. */
		      "beq 2f\n\t"
		      ".long 0x7c0005dd\n\t"	/* tsuspend. */
		      "2: .long 0x7c00059c\n\t"	/* tcheck cr0 */
		      "bf 2,1b" : : : "cr0");

	for (i = 0; i < 500; i++) {
		uint64_t rval = h_cede();

		if (rval != H_SUCCESS)
			break;
		mdelay(5);
	}

	report("H_CEDE TM", i == 500);
}

struct {
	const char *name;
	void (*func)(int argc, char **argv);
} hctests[] = {
	{ "h_cede_tm", test_h_cede_tm },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	bool all, has_tm;
	int i;

	report_prefix_push("tm");

	has_tm = all_cpus_have_tm();
	report_xfail("TM available in 'ibm,pa-features' property",
		     !has_tm, has_tm);
	if (!has_tm)
		return report_summary();

	all = argc == 1 || !strcmp(argv[1], "all");

	for (i = 0; hctests[i].name != NULL; i++) {
		if (all || strcmp(argv[1], hctests[i].name) == 0) {
			report_prefix_push(hctests[i].name);
			hctests[i].func(argc, argv);
			report_prefix_pop();
		}
	}

	return report_summary();
}
