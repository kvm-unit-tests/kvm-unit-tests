/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CPU Topology
 *
 * Copyright IBM Corp. 2022, 2023
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

static int check_cpu(union topology_cpu *cpu,
		     union topology_container *parent)
{
	report_prefix_pushf("%d:%d:%d:%d", cpu->d, cpu->pp, cpu->type, cpu->origin);

	report(!(cpu->raw[0] & CPUS_TLE_RES_BITS), "reserved bits %016lx",
	       cpu->raw[0] & CPUS_TLE_RES_BITS);

	report(cpu->type == CPU_TYPE_IFL, "type IFL");

	if (cpu->d)
		report(cpu->pp == POLARIZATION_VERTICAL_HIGH ||
		       cpu->pp == POLARIZATION_HORIZONTAL,
		       "Dedicated CPUs are either horizontally polarized or have high entitlement");
	else
		report_skip("Not dedicated");

	report_prefix_pop();

	return __builtin_popcountl(cpu->mask);
}

static union topology_container *check_child_cpus(struct sysinfo_15_1_x *info,
						  union topology_container *cont,
						  union topology_cpu *child,
						  unsigned int *cpus_in_masks)
{
	void *last = ((void *)info) + info->length;
	union topology_cpu *prev_cpu = NULL;
	bool correct_ordering = true;
	unsigned int cpus = 0;
	int i;

	for (i = 0; (void *)&child[i] < last && child[i].nl == 0; prev_cpu = &child[i++]) {
		cpus += check_cpu(&child[i], cont);
		if (prev_cpu) {
			if (prev_cpu->type > child[i].type) {
				report_info("Incorrect ordering wrt type for child %d", i);
				correct_ordering = false;
			}
			if (prev_cpu->type < child[i].type)
				continue;
			if (prev_cpu->pp < child[i].pp) {
				report_info("Incorrect ordering wrt polarization for child %d", i);
				correct_ordering = false;
			}
			if (prev_cpu->pp > child[i].pp)
				continue;
			if (!prev_cpu->d && child[i].d) {
				report_info("Incorrect ordering wrt dedication for child %d", i);
				correct_ordering = false;
			}
			if (prev_cpu->d && !child[i].d)
				continue;
			if (prev_cpu->origin > child[i].origin) {
				report_info("Incorrect ordering wrt origin for child %d", i);
				correct_ordering = false;
			}
		}
	}
	report(correct_ordering, "children correctly ordered");
	report(cpus <= expected_topo_lvl[0], "%d children <= max of %d",
	       cpus, expected_topo_lvl[0]);
	*cpus_in_masks += cpus;

	return (union topology_container *)&child[i];
}

static union topology_container *check_container(struct sysinfo_15_1_x *info,
						 union topology_container *cont,
						 union topology_entry *child,
						 unsigned int *cpus_in_masks);

static union topology_container *check_child_containers(struct sysinfo_15_1_x *info,
							union topology_container *cont,
							union topology_container *child,
							unsigned int *cpus_in_masks)
{
	void *last = ((void *)info) + info->length;
	union topology_container *entry;
	int i;

	for (i = 0, entry = child; (void *)entry < last && entry->nl == cont->nl - 1; i++) {
		entry = check_container(info, entry, (union topology_entry *)(entry + 1),
					cpus_in_masks);
	}
	if (max_nested_lvl == info->mnest)
		report(i <= expected_topo_lvl[cont->nl - 1], "%d children <= max of %d",
		       i, expected_topo_lvl[cont->nl - 1]);

	return entry;
}

static union topology_container *check_container(struct sysinfo_15_1_x *info,
						 union topology_container *cont,
						 union topology_entry *child,
						 unsigned int *cpus_in_masks)
{
	union topology_container *entry;

	report_prefix_pushf("%d", cont->id);

	report(cont->nl - 1 == child->nl, "Level %d one above child level %d",
	       cont->nl, child->nl);
	report(!(cont->raw & CONTAINER_TLE_RES_BITS), "reserved bits %016lx",
	       cont->raw & CONTAINER_TLE_RES_BITS);

	if (cont->nl > 1)
		entry = check_child_containers(info, cont, &child->container, cpus_in_masks);
	else
		entry = check_child_cpus(info, cont, &child->cpu, cpus_in_masks);

	report_prefix_pop();
	return entry;
}

static void check_topology_list(struct sysinfo_15_1_x *info, int sel2)
{
	union topology_container dummy = { .nl = sel2, .id = 0 };
	unsigned int cpus_in_masks = 0;

	report_prefix_push("TLE");

	check_container(info, &dummy, info->tle, &cpus_in_masks);
	report(cpus_in_masks == number_of_cpus,
	       "Number of CPUs %d equals  %d CPUs in masks",
	       number_of_cpus, cpus_in_masks);

	report_prefix_pop();
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
	check_topology_list(info, sel2);

vertical:
	report_prefix_pop();
	report_prefix_pushf("V");

	cc = ptf(PTF_REQ_VERTICAL, &rc);
	if (cc != 0 && rc != PTF_ERR_ALRDY_POLARIZED) {
		report_fail("Unable to set vertical polarization");
		goto end;
	}

	stsi_check_header(info, sel2);
	check_topology_list(info, sel2);
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
