/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Channel Subsystem tests
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 */

#include <libcflat.h>
#include <interrupt.h>
#include <hardware.h>

#include <asm/arch_def.h>
#include <asm/page.h>

#include <malloc_io.h>
#include <css.h>

#define DEFAULT_CU_TYPE		0x3832 /* virtio-ccw */
static unsigned long cu_type = DEFAULT_CU_TYPE;

static int test_device_sid;
static struct senseid *senseid;
struct ccw1 *ccw;

char alignment_test_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static void test_enumerate(void)
{
	test_device_sid = css_enumerate();
	if (test_device_sid & SCHID_ONE) {
		report_pass("Schid of first I/O device: 0x%08x", test_device_sid);
		return;
	}
	report_fail("No I/O device found");
}

static void test_enable(void)
{
	int cc;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	cc = css_enable(test_device_sid, IO_SCH_ISC);

	report(cc == 0, "Enable subchannel %08x", test_device_sid);
}

/*
 * test_sense
 * Pre-requisites:
 * - We need the test device as the first recognized
 *   device by the enumeration.
 */
static void test_sense(void)
{
	int ret;
	int len;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	ret = css_enable(test_device_sid, IO_SCH_ISC);
	if (ret) {
		report_fail("Could not enable the subchannel: %08x",
			    test_device_sid);
		return;
	}

	lowcore.io_int_param = 0;

	senseid = alloc_io_mem(sizeof(*senseid), 0);
	if (!senseid) {
		report_fail("Allocation of senseid");
		return;
	}

	ccw = ccw_alloc(CCW_CMD_SENSE_ID, senseid, sizeof(*senseid), CCW_F_SLI);
	if (!ccw) {
		report_fail("Allocation of CCW");
		goto error_ccw;
	}

	ret = start_ccw1_chain(test_device_sid, ccw);
	if (ret) {
		report_fail("Starting CCW chain");
		goto error;
	}

	if (wait_and_check_io_completion(test_device_sid) < 0)
		goto error;

	/* Test transfer completion */
	report_prefix_push("ssch transfer completion");

	ret = css_residual_count(test_device_sid);

	if (ret < 0) {
		report_info("no valid residual count");
	} else if (ret != 0) {
		len = sizeof(*senseid) - ret;
		if (ret && len < CSS_SENSEID_COMMON_LEN) {
			report_fail("transferred a too short length: %d", ret);
			goto error;
		} else if (ret && len)
			report_info("transferred a shorter length: %d", len);
	}

	if (senseid->reserved != 0xff) {
		report_fail("transferred garbage: 0x%02x", senseid->reserved);
		goto error;
	}

	report_prefix_pop();

	report_info("reserved 0x%02x cu_type 0x%04x cu_model 0x%02x dev_type 0x%04x dev_model 0x%02x",
		    senseid->reserved, senseid->cu_type, senseid->cu_model,
		    senseid->dev_type, senseid->dev_model);

	report(senseid->cu_type == cu_type, "cu_type expected 0x%04x got 0x%04x",
	       (uint16_t)cu_type, senseid->cu_type);

error:
	free_io_mem(ccw, sizeof(*ccw));
error_ccw:
	free_io_mem(senseid, sizeof(*senseid));
}

static void sense_id(void)
{
	assert(!start_ccw1_chain(test_device_sid, ccw));

	assert(wait_and_check_io_completion(test_device_sid) >= 0);
}

static void css_init(void)
{
	assert(register_io_int_func(css_irq_io) == 0);
	lowcore.io_int_param = 0;

	report(get_chsc_scsc(), "Store Channel Characteristics");
}

static void test_schm(void)
{
	if (css_test_general_feature(CSSC_EXTENDED_MEASUREMENT_BLOCK))
		report_info("Extended measurement block available");

	/* bits 59-63 of MB address must be 0  if MBU is defined */
	report_prefix_push("Unaligned operand");
	expect_pgm_int();
	schm((void *)0x01, SCHM_MBU);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
	report_prefix_pop();

	/* bits 36-61 of register 1 (flags) must be 0 */
	report_prefix_push("Bad flags");
	expect_pgm_int();
	schm(NULL, 0xfffffffc);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
	report_prefix_pop();

	/* SCHM is a privilege operation */
	report_prefix_push("Privilege");
	enter_pstate();
	expect_pgm_int();
	schm(NULL, SCHM_MBU);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	/* Normal operation */
	report_prefix_push("Normal operation");
	schm(NULL, SCHM_MBU);
	report_pass("SCHM call without address");
	report_prefix_pop();
}

#define SCHM_UPDATE_CNT 10
static bool start_measuring(uint64_t mbo, uint16_t mbi, bool fmt1)
{
	int i;

	senseid = alloc_io_mem(sizeof(*senseid), 0);
	assert(senseid);

	ccw = ccw_alloc(CCW_CMD_SENSE_ID, senseid, sizeof(*senseid), CCW_F_SLI);
	assert(ccw);

	if (!css_enable_mb(test_device_sid, mbo, mbi, PMCW_MBUE, fmt1)) {
		report_abort("Enabling measurement block failed");
		return false;
	}

	for (i = 0; i < SCHM_UPDATE_CNT; i++)
		sense_id();

	free_io_mem(ccw, sizeof(*ccw));
	free_io_mem(senseid, sizeof(*senseid));

	return true;
}

/*
 * test_schm_fmt0:
 * With measurement block format 0 a memory space is shared
 * by all subchannels, each subchannel can provide an index
 * for the measurement block facility to store the measurements.
 */
static void test_schm_fmt0(void)
{
	struct measurement_block_format0 *mb0;
	int shared_mb_size = 2 * sizeof(struct measurement_block_format0);

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	/* Allocate zeroed Measurement block */
	mb0 = alloc_io_mem(shared_mb_size, 0);
	if (!mb0) {
		report_abort("measurement_block_format0 allocation failed");
		return;
	}

	schm(NULL, 0); /* Stop any previous measurement */
	schm(mb0, SCHM_MBU);

	/* Expect success */
	report_prefix_push("Valid MB address and index 0");
	report(start_measuring(0, 0, false) &&
	       mb0->ssch_rsch_count == SCHM_UPDATE_CNT,
	       "SSCH measured %d", mb0->ssch_rsch_count);
	report_prefix_pop();

	/* Clear the measurement block for the next test */
	memset(mb0, 0, shared_mb_size);

	/* Expect success */
	report_prefix_push("Valid MB address and index 1");
	if (start_measuring(0, 1, false))
		report(mb0[1].ssch_rsch_count == SCHM_UPDATE_CNT,
		       "SSCH measured %d", mb0[1].ssch_rsch_count);
	report_prefix_pop();

	/* Stop the measurement */
	css_disable_mb(test_device_sid);
	schm(NULL, 0);

	free_io_mem(mb0, shared_mb_size);
}

static void msch_with_wrong_fmt1_mbo(unsigned int schid, uint64_t mb)
{
	struct pmcw *pmcw = &schib.pmcw;
	int cc;

	/* Read the SCHIB for this subchannel */
	cc = stsch(schid, &schib);
	if (cc) {
		report_fail("stsch: sch %08x failed with cc=%d", schid, cc);
		return;
	}

	/* Update the SCHIB to enable the measurement block */
	pmcw->flags |= PMCW_MBUE;
	pmcw->flags2 |= PMCW_MBF1;
	schib.mbo = mb;

	/* Tell the CSS we want to modify the subchannel */
	expect_pgm_int();
	cc = msch(schid, &schib);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
}

/*
 * test_schm_fmt1:
 * With measurement block format 1 the measurement block is
 * dedicated to a subchannel.
 */
static void test_schm_fmt1(void)
{
	struct measurement_block_format1 *mb1;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	if (!css_test_general_feature(CSSC_EXTENDED_MEASUREMENT_BLOCK)) {
		report_skip("Extended measurement block not available");
		return;
	}

	/* Allocate zeroed Measurement block */
	mb1 = alloc_io_mem(sizeof(struct measurement_block_format1), 0);
	if (!mb1) {
		report_abort("measurement_block_format1 allocation failed");
		return;
	}

	schm(NULL, 0); /* Stop any previous measurement */
	schm(0, SCHM_MBU);

	/* Expect error for non aligned MB */
	report_prefix_push("Unaligned MB origin");
	msch_with_wrong_fmt1_mbo(test_device_sid, (uint64_t)mb1 + 1);
	report_prefix_pop();

	/* Clear the measurement block for the next test */
	memset(mb1, 0, sizeof(*mb1));

	/* Expect success */
	report_prefix_push("Valid MB origin");
	if (start_measuring((u64)mb1, 0, true))
		report(mb1->ssch_rsch_count == SCHM_UPDATE_CNT,
		       "SSCH measured %d", mb1->ssch_rsch_count);
	report_prefix_pop();

	/* Stop the measurement */
	css_disable_mb(test_device_sid);
	schm(NULL, 0);

	free_io_mem(mb1, sizeof(struct measurement_block_format1));
}

static void test_msch(void)
{
	int invalid_pmcw_flags[] = {0, 1, 6, 7};
	struct schib test_schib;
	uint16_t old_pmcw_flags;
	const int align_to = 4;
	int invalid_flag;
	int cc;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	cc = stsch(test_device_sid, &schib);
	if (cc) {
		report_fail("stsch: sch %08x failed with cc=%d", test_device_sid, cc);
		return;
	}

	report_prefix_push("Unaligned");
	for (int i = 1; i < align_to; i *= 2) {
		report_prefix_pushf("%d", i);

		expect_pgm_int();
		msch(test_device_sid, (struct schib *)(alignment_test_page + i));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

		report_prefix_pop();
	}
	report_prefix_pop();

	report_prefix_push("Invalid SCHIB");
	old_pmcw_flags = schib.pmcw.flags;
	for (int i = 0; i < ARRAY_SIZE(invalid_pmcw_flags); i++) {
		invalid_flag = invalid_pmcw_flags[i];

		report_prefix_pushf("PMCW flag bit %d set", invalid_flag);

		schib.pmcw.flags = old_pmcw_flags | BIT(15 - invalid_flag);
		expect_pgm_int();
		msch(test_device_sid, &schib);
		check_pgm_int_code(PGM_INT_CODE_OPERAND);

		cc = stsch(test_device_sid, &test_schib);
		report(!cc, "STSCH succeeded");
		report(!(test_schib.pmcw.flags & BIT(15 - invalid_flag)), "Clear on STSCH");

		report_prefix_pop();
	}
	report_prefix_pop();

	schib.pmcw.flags = old_pmcw_flags;
}

static void check_stcrw_no_crw_available(void)
{
	uint32_t crw = 0xfeedc0fe;
	int cc;

	report_prefix_push("No CRW available");
	cc = stcrw(&crw);
	report(cc == 1, "cc == 1");
	report(!crw, "stored zeroes in crw");
	report_prefix_pop();
}

static int check_stcrw_crw_available(void)
{
	const uint32_t magic = 0xfeedc0fe;
	uint32_t crw = magic;
	int cc;

	report_prefix_push("CRW available");
	cc = stcrw(&crw);
	report(!cc, "cc is zero");
	report(crw != magic, "stored crw");
	report_prefix_pop();

	return crw;
}

static uint32_t crw_get_rsc(uint32_t crw)
{
	const int rsc_begin = 4;
	const int rsc_end = 8;

	return (crw & GENMASK(31 - rsc_begin, 31 - rsc_end)) >> 24;
}

#define CRW_RSC_CHP 4
static void test_stcrw(void)
{
	const int align_to = 4;
	int res;
	uint32_t crw;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	report_prefix_push("Unaligned");
	for (int i = 1; i < align_to; i *= 2) {
		report_prefix_pushf("%d", i);

		expect_pgm_int();
		stcrw((uint32_t *)(alignment_test_page + i));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

		report_prefix_pop();
	}
	report_prefix_pop();

	report_prefix_push("No CRW available initally");
	check_stcrw_no_crw_available();
	report_prefix_pop();

	res = css_generate_crw(test_device_sid);
	if (res) {
		report_skip("Couldn't generate CRW");
		report_prefix_pop();
		return;
	}

	crw = check_stcrw_crw_available();

	report_prefix_push("CRW available");
	report(crw_get_rsc(crw) == CRW_RSC_CHP, "CRW has Channel Path RSC");
	report_prefix_pop();

	report_prefix_push("No more CRWs pending");
	check_stcrw_no_crw_available();
	report_prefix_pop();
}

static void test_ssch(void)
{
	const int align_to = 4;
	struct orb orb;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	report_prefix_push("Unaligned");
	for (int i = 1; i < align_to; i *= 2) {
		report_prefix_pushf("%d", i);

		expect_pgm_int();
		ssch(test_device_sid, (struct orb *)(alignment_test_page + i));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

		report_prefix_pop();
	}
	report_prefix_pop();

	report_prefix_push("Invalid ORB");

	memset(&orb, 0xff, sizeof(orb));
	expect_pgm_int();
	ssch(test_device_sid, &orb);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);

	report_prefix_pop();
}

static void test_stsch(void)
{
	const int align_to = 4;
	struct schib schib;
	int cc;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	report_prefix_push("Unaligned");
	for (int i = 1; i < align_to; i *= 2) {
		report_prefix_pushf("%d", i);

		expect_pgm_int();
		stsch(test_device_sid, (struct schib *)(alignment_test_page + i));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

		report_prefix_pop();
	}
	report_prefix_pop();

	report_prefix_push("Invalid subchannel number");
	cc = stsch(0x0001ffff, &schib);
	report(cc == 3, "Channel not operational");
	report_prefix_pop();

	/*
	 * No matter if multiple-subchannel-set facility is installed, bit 47
	 * always needs to be 1.
	 */
	report_prefix_push("Bit 47 in SID is zero");
	expect_pgm_int();
	stsch(0x0000ffff, &schib);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
	report_prefix_pop();
}

/*
 * According to architecture MSCH does ignore bit 5 of the second word
 * but STSCH will store bit 5 as zero.
 */
static void test_pmcw_bit5(void)
{
	int cc;
	uint16_t old_pmcw_flags;

	cc = stsch(test_device_sid, &schib);
	if (cc) {
		report_fail("stsch: sch %08x failed with cc=%d", test_device_sid, cc);
		return;
	}
	old_pmcw_flags = schib.pmcw.flags;

	report_prefix_push("Bit 5 set");

	schib.pmcw.flags = old_pmcw_flags | BIT(15 - 5);
	cc = msch(test_device_sid, &schib);
	report(!cc, "MSCH cc == 0");

	cc = stsch(test_device_sid, &schib);
	report(!cc, "STSCH cc == 0");
	report(!(schib.pmcw.flags & BIT(15 - 5)), "STSCH PMCW Bit 5 is clear");

	report_prefix_pop();

	report_prefix_push("Bit 5 clear");

	schib.pmcw.flags = old_pmcw_flags & ~BIT(15 - 5);
	cc = msch(test_device_sid, &schib);
	report(!cc, "MSCH cc == 0");

	cc = stsch(test_device_sid, &schib);
	report(!cc, "STSCH cc == 0");
	report(!(schib.pmcw.flags & BIT(15 - 5)), "STSCH PMCW Bit 5 is clear");

	report_prefix_pop();
}

static void test_tsch(void)
{
	const int align_to = 4;
	struct irb irb;
	int cc;

	if (!test_device_sid) {
		report_skip("No device");
		return;
	}

	report_prefix_push("Unaligned");
	for (int i = 1; i < align_to; i *= 2) {
		report_prefix_pushf("%d", i);

		expect_pgm_int();
		tsch(test_device_sid, (struct irb *)(alignment_test_page + i));
		check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);

		report_prefix_pop();
	}
	report_prefix_pop();

	report_prefix_push("Invalid subchannel number");
	cc = tsch(0x0001ffff, &irb);
	report(cc == 3, "Channel not operational");
	report_prefix_pop();

	report_prefix_push("Bit 47 in SID is zero");
	expect_pgm_int();
	tsch(0x0000ffff, &irb);
	check_pgm_int_code(PGM_INT_CODE_OPERAND);
	report_prefix_pop();
}

static struct {
	const char *name;
	void (*func)(void);
} tests[] = {
	/* The css_init test is needed to initialize the CSS Characteristics */
	{ "initialize CSS (chsc)", css_init },
	{ "enumerate (stsch)", test_enumerate },
	{ "enable (msch)", test_enable },
	{ "sense (ssch/tsch)", test_sense },
	{ "measurement block (schm)", test_schm },
	{ "measurement block format0", test_schm_fmt0 },
	{ "measurement block format1", test_schm_fmt1 },
	{ "msch", test_msch },
	{ "stcrw", test_stcrw },
	{ "ssch", test_ssch },
	{ "stsch", test_stsch },
	{ "pmcw bit 5 ignored", test_pmcw_bit5 },
	{ "tsch", test_tsch },
	{ NULL, NULL }
};

int main(int argc, char *argv[])
{
	int i;

	report_prefix_push("Channel Subsystem");

	/* There's no guarantee where our devices are without qemu */
	if (!host_is_qemu()) {
		report_skip("Not running under QEMU");
		goto done;
	}

	enable_io_isc(0x80 >> IO_SCH_ISC);
	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		tests[i].func();
		report_prefix_pop();
	}

done:
	report_prefix_pop();
	return report_summary();
}
