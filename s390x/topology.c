/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CPU Topology
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 */

#include <libcflat.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/facility.h>
#include <asm/barrier.h>
#include <smp.h>
#include <sclp.h>
#include <s390x/hardware.h>
#include <s390x/stsi.h>

static uint8_t pagebuf[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static int max_nested_lvl;
static int number_of_cpus;
static int cpus_in_masks;
static int max_cpus;

/*
 * Topology level as defined by architecture, all levels exists with
 * a single container unless overwritten by the QEMU -smp parameter.
 */
static int expected_topo_lvl[CPU_TOPOLOGY_MAX_LEVEL] = { 1, 1, 1, 1, 1, 1 };

#define PTF_REQ_HORIZONTAL	0
#define PTF_REQ_VERTICAL	1
#define PTF_CHECK		2

#define PTF_ERR_NO_REASON	0
#define PTF_ERR_ALRDY_POLARIZED	1
#define PTF_ERR_IN_PROGRESS	2

extern int diag308_load_reset(u64);

static int ptf(unsigned long fc, unsigned long *rc)
{
	int cc;

	asm volatile(
		"	ptf	%1	\n"
		"       ipm     %0	\n"
		"       srl     %0,28	\n"
		: "=d" (cc), "+d" (fc)
		:
		: "cc");

	*rc = fc >> 8;
	return cc;
}

static void check_privilege(int fc)
{
	unsigned long rc;

	report_prefix_pushf("Privileged fc %d", fc);
	enter_pstate();
	expect_pgm_int();
	ptf(fc, &rc);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static void check_specifications(void)
{
	unsigned long error = 0;
	unsigned long ptf_bits;
	unsigned long rc;
	int i;

	report_prefix_push("Specifications");

	/* Function codes above 3 are undefined */
	for (i = 4; i < 255; i++) {
		expect_pgm_int();
		ptf(i, &rc);
		if (clear_pgm_int() != PGM_INT_CODE_SPECIFICATION) {
			report_fail("FC %d did not yield specification exception", i);
			error = 1;
		}
	}
	report(!error, "Undefined function codes");

	/* Reserved bits must be 0 */
	for (i = 8, error = 0; i < 64; i++) {
		ptf_bits = 0x01UL << i;
		expect_pgm_int();
		ptf(ptf_bits, &rc);
		if (clear_pgm_int() != PGM_INT_CODE_SPECIFICATION) {
			report_fail("Reserved bit %d did not yield specification exception", i);
			error = 1;
		}
	}

	report(!error, "Reserved bits");

	report_prefix_pop();
}

static void check_polarization_change(void)
{
	unsigned long rc;
	int cc;

	report_prefix_push("Polarization change");

	/* We expect a clean state through reset */
	assert(diag308_load_reset(1));

	/*
	 * Set vertical polarization to verify that RESET sets
	 * horizontal polarization back.
	 */
	cc = ptf(PTF_REQ_VERTICAL, &rc);
	report(cc == 0, "Set vertical polarization.");

	assert(diag308_load_reset(1));

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 0, "Reset should clear topology report");

	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	report(cc == 2 && rc == PTF_ERR_ALRDY_POLARIZED,
	       "After RESET polarization is horizontal");

	/* Flip between vertical and horizontal polarization */
	cc = ptf(PTF_REQ_VERTICAL, &rc);
	report(cc == 0, "Change to vertical");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 1, "Should report change after horizontal -> vertical");

	cc = ptf(PTF_REQ_VERTICAL, &rc);
	report(cc == 2 && rc == PTF_ERR_ALRDY_POLARIZED, "Double change to vertical");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 0, "Should not report change after vertical -> vertical");

	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	report(cc == 0, "Change to horizontal");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 1, "Should report change after vertical -> horizontal");

	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	report(cc == 2 && rc == PTF_ERR_ALRDY_POLARIZED, "Double change to horizontal");

	cc = ptf(PTF_CHECK, &rc);
	report(cc == 0, "Should not report change after horizontal -> horizontal");

	report_prefix_pop();
}

static void test_ptf(void)
{
	check_privilege(PTF_REQ_HORIZONTAL);
	check_privilege(PTF_REQ_VERTICAL);
	check_privilege(PTF_CHECK);
	check_specifications();
	check_polarization_change();
}

/*
 * stsi_check_maxcpus
 * @info: Pointer to the stsi information
 *
 * The product of the numbers of containers per level
 * is the maximum number of CPU allowed by the machine.
 */
static void stsi_check_maxcpus(struct sysinfo_15_1_x *info)
{
	int n, i;

	for (i = 0, n = 1; i < CPU_TOPOLOGY_MAX_LEVEL; i++)
		n *= info->mag[i] ?: 1;

	report(n == max_cpus, "Calculated max CPUs: %d", n);
}

/*
 * stsi_check_header
 * @info: Pointer to the stsi information
 * @sel2: stsi selector 2 value
 *
 * MAG field should match the architecture defined containers
 * when MNEST as returned by SCLP matches MNEST of the SYSIB.
 */
static void stsi_check_header(struct sysinfo_15_1_x *info, int sel2)
{
	int i;

	report_prefix_push("Header");

	/* Header is 16 bytes, each TLE 8 or 16, therefore alignment must be 8 at least */
	report(IS_ALIGNED(info->length, 8), "Length %d multiple of 8", info->length);
	report(info->length < PAGE_SIZE, "Length %d in bounds", info->length);
	report(sel2 == info->mnest, "Valid mnest");
	stsi_check_maxcpus(info);

	/*
	 * It is not clear how the MAG fields are calculated when mnest
	 * in the SYSIB 15.x is different from the maximum nested level
	 * in the SCLP info, so we skip here for now.
	 */
	if (max_nested_lvl != info->mnest) {
		report_skip("No specification on layer aggregation");
		goto done;
	}

	/*
	 * MAG up to max_nested_lvl must match the architecture
	 * defined containers.
	 */
	for (i = 0; i < max_nested_lvl; i++)
		report(info->mag[CPU_TOPOLOGY_MAX_LEVEL - i - 1] == expected_topo_lvl[i],
		       "MAG %d field match %d == %d",
		       i + 1,
		       info->mag[CPU_TOPOLOGY_MAX_LEVEL - i - 1],
		       expected_topo_lvl[i]);

	/* Above max_nested_lvl the MAG field must be null */
	for (; i < CPU_TOPOLOGY_MAX_LEVEL; i++)
		report(info->mag[CPU_TOPOLOGY_MAX_LEVEL - i - 1] == 0,
		       "MAG %d field match %d == %d", i + 1,
		       info->mag[CPU_TOPOLOGY_MAX_LEVEL - i - 1], 0);

done:
	report_prefix_pop();
}

/**
 * check_tle:
 * @tc: pointer to first TLE
 *
 * Recursively check the containers TLEs until we
 * find a CPU TLE.
 */
static uint8_t *check_tle(void *tc)
{
	struct topology_container *container = tc;
	struct topology_cpu *cpus;
	int n;

	if (container->nl) {
		report_info("NL: %d id: %d", container->nl, container->id);

		report(!(*(uint64_t *)tc & CONTAINER_TLE_RES_BITS),
		       "reserved bits %016lx",
		       *(uint64_t *)tc & CONTAINER_TLE_RES_BITS);

		return check_tle(tc + sizeof(*container));
	}

	report_info("NL: %d", container->nl);
	cpus = tc;

	report(!(*(uint64_t *)tc & CPUS_TLE_RES_BITS), "reserved bits %016lx",
	       *(uint64_t *)tc & CPUS_TLE_RES_BITS);

	report(cpus->type == CPU_TYPE_IFL, "type IFL");

	report_info("origin: %d", cpus->origin);
	report_info("mask: %016lx", cpus->mask);
	report_info("dedicated: %d entitlement: %d", cpus->d, cpus->pp);

	n = __builtin_popcountl(cpus->mask);
	report(n <= expected_topo_lvl[0], "CPUs per mask: %d out of max %d",
	       n, expected_topo_lvl[0]);
	cpus_in_masks += n;

	if (!cpus->d)
		report_skip("Not dedicated");
	else
		report(cpus->pp == POLARIZATION_VERTICAL_HIGH ||
		       cpus->pp == POLARIZATION_HORIZONTAL,
		       "Dedicated CPUs are either horizontally polarized or have high entitlement");

	return tc + sizeof(*cpus);
}

/**
 * stsi_check_tle_coherency:
 * @info: Pointer to the stsi information
 *
 * We verify that we get the expected number of Topology List Entry
 * containers for a specific level.
 */
static void stsi_check_tle_coherency(struct sysinfo_15_1_x *info)
{
	void *tc, *end;

	report_prefix_push("TLE");
	cpus_in_masks = 0;

	tc = info->tle;
	end = (void *)info + info->length;

	while (tc < end)
		tc = check_tle(tc);

	report(cpus_in_masks == number_of_cpus, "CPUs in mask %d",
	       cpus_in_masks);

	report_prefix_pop();
}

/**
 * stsi_get_sysib:
 * @info: pointer to the STSI info structure
 * @sel2: the selector giving the topology level to check
 *
 * Fill the sysinfo_15_1_x info structure and check the
 * SYSIB header.
 *
 * Returns instruction validity.
 */
static int stsi_get_sysib(struct sysinfo_15_1_x *info, int sel2)
{
	int ret;

	report_prefix_pushf("SYSIB");

	ret = stsi(info, 15, 1, sel2);

	if (max_nested_lvl >= sel2) {
		report(!ret, "Valid instruction");
	} else {
		report(ret, "Invalid instruction");
	}

	report_prefix_pop();

	return ret;
}

/**
 * check_sysinfo_15_1_x:
 * @info: pointer to the STSI info structure
 * @sel2: the selector giving the topology level to check
 *
 * Check if the validity of the STSI instruction and then
 * calls specific checks on the information buffer.
 */
static void check_sysinfo_15_1_x(struct sysinfo_15_1_x *info, int sel2)
{
	int ret;
	int cc;
	unsigned long rc;

	report_prefix_pushf("15_1_%d", sel2);

	ret = stsi_get_sysib(info, sel2);
	if (ret) {
		report_skip("Selector 2 not supported by architecture");
		goto end;
	}

	report_prefix_pushf("H");
	cc = ptf(PTF_REQ_HORIZONTAL, &rc);
	if (cc != 0 && rc != PTF_ERR_ALRDY_POLARIZED) {
		report_fail("Unable to set horizontal polarization");
		goto vertical;
	}

	stsi_check_header(info, sel2);
	stsi_check_tle_coherency(info);

vertical:
	report_prefix_pop();
	report_prefix_pushf("V");

	cc = ptf(PTF_REQ_VERTICAL, &rc);
	if (cc != 0 && rc != PTF_ERR_ALRDY_POLARIZED) {
		report_fail("Unable to set vertical polarization");
		goto end;
	}

	stsi_check_header(info, sel2);
	stsi_check_tle_coherency(info);
	report_prefix_pop();

end:
	report_prefix_pop();
}

/*
 * The Maximum Nested level is given by SCLP READ_SCP_INFO if the MNEST facility
 * is available.
 * If the MNEST facility is not available, sclp_get_stsi_mnest  returns 0 and the
 * Maximum Nested level is 2
 */
#define S390_DEFAULT_MNEST	2
static int sclp_get_mnest(void)
{
	return sclp_get_stsi_mnest() ?: S390_DEFAULT_MNEST;
}

static int expected_num_cpus(void)
{
	int i;
	int ncpus = 1;

	for (i = 0; i < CPU_TOPOLOGY_MAX_LEVEL; i++)
		ncpus *= expected_topo_lvl[i] ?: 1;

	return ncpus;
}

/**
 * test_stsi:
 *
 * Retrieves the maximum nested topology level supported by the architecture
 * and the number of CPUs.
 * Calls the checking for the STSI instruction in sel2 reverse level order
 * from 6 (CPU_TOPOLOGY_MAX_LEVEL) to 2 to have the most interesting level,
 * the one triggering a topology-change-report-pending condition, level 2,
 * at the end of the report.
 *
 */
static void test_stsi(void)
{
	int sel2;

	max_cpus = expected_num_cpus();
	report_info("Architecture max CPUs: %d", max_cpus);

	max_nested_lvl = sclp_get_mnest();
	report_info("SCLP maximum nested level : %d", max_nested_lvl);

	number_of_cpus = sclp_get_cpu_num();
	report_info("SCLP number of CPU: %d", number_of_cpus);

	/* STSI selector 2 can takes values between 2 and 6 */
	for (sel2 = 6; sel2 >= 2; sel2--)
		check_sysinfo_15_1_x((struct sysinfo_15_1_x *)pagebuf, sel2);
}

/**
 * parse_topology_args:
 * @argc: number of arguments
 * @argv: argument array
 *
 * This function initialize the architecture topology levels
 * which should be the same as the one provided by the hypervisor.
 *
 * We use the current names found in IBM/Z literature, Linux and QEMU:
 * cores, sockets/packages, books, drawers and nodes to facilitate the
 * human machine interface but store the result in a machine abstract
 * array of architecture topology levels.
 * Note that when QEMU uses socket as a name for the topology level 1
 * Linux uses package or physical_package.
 */
static void parse_topology_args(int argc, char **argv)
{
	int i;
	static const char * const levels[] = { "cores", "sockets",
					       "books", "drawers" };

	for (i = 1; i < argc; i++) {
		char *flag = argv[i];
		int level;

		if (flag[0] != '-')
			report_abort("Argument is expected to begin with '-'");
		flag++;
		for (level = 0; level < ARRAY_SIZE(levels); level++) {
			if (!strcmp(levels[level], flag))
				break;
		}
		if (level == ARRAY_SIZE(levels))
			report_abort("Unknown parameter %s", flag);

		expected_topo_lvl[level] = atol(argv[++i]);
		report_info("%s: %d", levels[level], expected_topo_lvl[level]);
	}
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	{ "PTF", test_ptf },
	{ "STSI", test_stsi },
	{ NULL, NULL }
};

int main(int argc, char *argv[])
{
	int i;

	report_prefix_push("CPU Topology");

	parse_topology_args(argc, argv);

	if (!test_facility(11)) {
		report_skip("Topology facility not present");
		goto end;
	}

	report_info("Virtual machine level %ld", stsi_get_fc());

	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}

end:
	report_prefix_pop();
	return report_summary();
}
