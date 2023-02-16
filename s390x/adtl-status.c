/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests sigp store additional status order
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *    Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/facility.h>
#include <asm-generic/barrier.h>
#include <asm/sigp.h>
#include <asm/vector.h>

#include <smp.h>
#include <gs.h>

static int testflag = 0;

#define INVALID_CPU_ADDRESS -4711

struct mcesa_lc12 {
	uint8_t vregs[0x200];		      /* 0x000 */
	uint8_t reserved200[0x400 - 0x200];   /* 0x200 */
	struct gs_cb gs_cb;                   /* 0x400 */
	uint8_t reserved420[0x800 - 0x420];   /* 0x420 */
	uint8_t reserved800[0x1000 - 0x800];  /* 0x800 */
};

static struct mcesa_lc12 adtl_status __attribute__((aligned(4096)));

static uint8_t expected_vec_contents[VEC_REGISTER_NUM][VEC_REGISTER_SIZE];

static struct gs_cb gs_cb;
static struct gs_epl gs_epl;

static bool memisset(void *s, int c, size_t n)
{
	uint8_t *p = s;
	size_t i;

	for (i = 0; i < n; i++) {
		if (p[i] != c)
			return false;
	}

	return true;
}

static void wait_for_flag(void)
{
	while (!testflag)
		mb();
}

static void set_flag(int val)
{
	mb();
	testflag = val;
	mb();
}

static void test_func(void)
{
	set_flag(1);
}

static bool have_adtl_status(void)
{
	return test_facility(133) || test_facility(129);
}

static void test_store_adtl_status(void)
{
	uint32_t status = -1;
	int cc;

	report_prefix_push("store additional status");

	if (!have_adtl_status()) {
		report_skip("no guarded-storage or vector facility installed");
		goto out;
	}

	memset(&adtl_status, 0xff, sizeof(adtl_status));

	report_prefix_push("running");
	smp_cpu_restart(1);

	cc = smp_sigp(1, SIGP_STORE_ADDITIONAL_STATUS,
		  (unsigned long)&adtl_status, &status);

	report(cc == 1, "CC = 1");
	report(status == SIGP_STATUS_INCORRECT_STATE, "status = INCORRECT_STATE");
	report(memisset(&adtl_status, 0xff, sizeof(adtl_status)),
	       "additional status not touched");

	report_prefix_pop();

	report_prefix_push("invalid CPU address");

	cc = sigp(INVALID_CPU_ADDRESS, SIGP_STORE_ADDITIONAL_STATUS,
		  (unsigned long)&adtl_status, &status);
	report(cc == 3, "CC = 3");
	report(memisset(&adtl_status, 0xff, sizeof(adtl_status)),
	       "additional status not touched");

	report_prefix_pop();

	report_prefix_push("unaligned");
	smp_cpu_stop(1);

	cc = smp_sigp(1, SIGP_STORE_ADDITIONAL_STATUS,
		  (unsigned long)&adtl_status + 256, &status);
	report(cc == 1, "CC = 1");
	report(status == SIGP_STATUS_INVALID_PARAMETER, "status = INVALID_PARAMETER");
	report(memisset(&adtl_status, 0xff, sizeof(adtl_status)),
	       "additional status not touched");

	report_prefix_pop();

out:
	report_prefix_pop();
}

static void test_store_adtl_status_unavail(void)
{
	uint32_t status = 0;
	int cc;

	report_prefix_push("store additional status unavailable");

	if (have_adtl_status()) {
		report_skip("guarded-storage or vector facility installed");
		goto out;
	}

	report_prefix_push("not accepted");
	smp_cpu_stop(1);

	memset(&adtl_status, 0xff, sizeof(adtl_status));

	cc = smp_sigp(1, SIGP_STORE_ADDITIONAL_STATUS,
		  (unsigned long)&adtl_status, &status);

	report(cc == 1, "CC = 1");
	report(status == SIGP_STATUS_INVALID_ORDER,
	       "status = INVALID_ORDER");
	report(memisset(&adtl_status, 0xff, sizeof(adtl_status)),
	       "additional status not touched");

	report_prefix_pop();

out:
	report_prefix_pop();
}

static void restart_write_vector(void)
{
	uint8_t *vec_reg;
	/* vlm handles at most 16 registers at a time */
	uint8_t *vec_reg_16_31 = &expected_vec_contents[16][0];
	uint64_t cr0, cr0_mask = ~BIT_ULL(CTL0_VECTOR);
	int i;

	for (i = 0; i < VEC_REGISTER_NUM; i++) {
		vec_reg = &expected_vec_contents[i][0];
		/* i+1 to avoid zero content */
		memset(vec_reg, i + 1, VEC_REGISTER_SIZE);
	}

	ctl_set_bit(0, CTL0_VECTOR);

	asm volatile (
		"	.machine z13\n"
		/* load vector registers */
		"	vlm 0,15, %[vec_reg_0_15]\n"
		"	vlm 16,31, %[vec_reg_16_31]\n"
		/* turn off vector instructions */
		"	stctg 0,0, %[cr0]\n"
		"	ng %[cr0_mask], %[cr0]\n"
		"	stg %[cr0_mask], %[cr0]\n"
		"	lctlg 0,0, %[cr0]\n"
		/* inform CPU 0 we are done by setting testflag to 1 */
		"	mvhi %[testflag], 1\n"
		/*
		 * infinite loop. function epilogue will restore floating point
		 * registers and hence destroy vector register contents
		 */
		"0:	j 0\n"
		: [cr0_mask] "+&d"(cr0_mask)
		: [vec_reg_0_15] "Q"(expected_vec_contents),
		  [vec_reg_16_31] "Q"(*vec_reg_16_31),
		  [cr0] "Q"(cr0),
		  [testflag] "T"(testflag)
		: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
		  "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18",
		  "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27",
		  "v28", "v29", "v30", "v31", "cc", "memory"
	);
}

static void cpu_write_magic_to_vector_regs(uint16_t cpu_idx)
{
	smp_cpu_stop(cpu_idx);

	set_flag(0);

	smp_cpu_start(cpu_idx, PSW_WITH_CUR_MASK(restart_write_vector));

	wait_for_flag();
}

static int adtl_status_check_unmodified_fields_for_lc(unsigned long lc)
{
	assert (!lc || (lc >= 10 && lc <= 12));

	if (lc <= 10 && !memisset(&adtl_status.gs_cb, 0xff, sizeof(adtl_status.gs_cb)))
		return false;

	if (!memisset(adtl_status.reserved200, 0xff, sizeof(adtl_status.reserved200)))
		return false;

	if (!memisset(adtl_status.reserved420, 0xff, sizeof(adtl_status.reserved420)))
		return false;

	if (!memisset(adtl_status.reserved800, 0xff, sizeof(adtl_status.reserved800)))
		return false;

	return true;
}

static void __store_adtl_status_vector_lc(unsigned long lc)
{
	uint32_t status = -1;
	int cc;

	report_prefix_pushf("LC %lu", lc);

	if (!test_facility(133) && lc) {
		report_skip("not supported, no guarded-storage facility");
		goto out;
	}

	cpu_write_magic_to_vector_regs(1);
	smp_cpu_stop(1);

	memset(&adtl_status, 0xff, sizeof(adtl_status));

	cc = smp_sigp(1, SIGP_STORE_ADDITIONAL_STATUS,
		  (unsigned long)&adtl_status | lc, &status);
	report(!cc, "CC = 0");

	report(!memcmp(adtl_status.vregs,
		       expected_vec_contents, sizeof(expected_vec_contents)),
	       "additional status contents match");

	report(adtl_status_check_unmodified_fields_for_lc(lc),
	       "no write outside expected fields");

	/*
	 * To avoid the floating point/vector registers being cleaned up, we
	 * stopped CPU1 right in the middle of a function. Hence the cleanup of
	 * the function didn't run yet and the stackpointer is messed up.
	 * Destroy and re-initalize the CPU to fix that.
	 */
	smp_cpu_destroy(1);
	smp_cpu_setup(1, PSW_WITH_CUR_MASK(test_func));

out:
	report_prefix_pop();
}

static void test_store_adtl_status_vector(void)
{
	report_prefix_push("store additional status vector");

	if (!test_facility(129)) {
		report_skip("vector facility not installed");
		goto out;
	}

	__store_adtl_status_vector_lc(0);
	__store_adtl_status_vector_lc(10);
	__store_adtl_status_vector_lc(11);
	__store_adtl_status_vector_lc(12);

out:
	report_prefix_pop();
}

static void restart_write_gs_regs(void)
{
	const unsigned long gs_area = 0x2000000;
	const unsigned long gsc = 25; /* align = 32 M, section size = 512K */

	ctl_set_bit(2, CTL2_GUARDED_STORAGE);

	gs_cb.gsd = gs_area | gsc;
	gs_cb.gssm = 0xfeedc0ffe;
	gs_cb.gs_epl_a = (uint64_t) &gs_epl;

	load_gs_cb(&gs_cb);

	set_flag(1);

	ctl_clear_bit(2, CTL2_GUARDED_STORAGE);

	/*
	 * Safe to return here. r14 will point to the endless loop in
	 * smp_cpu_setup_state.
	 */
}

static void cpu_write_to_gs_regs(uint16_t cpu_idx)
{
	smp_cpu_stop(cpu_idx);

	set_flag(0);

	smp_cpu_start(cpu_idx, PSW_WITH_CUR_MASK(restart_write_gs_regs));

	wait_for_flag();
}

static void __store_adtl_status_gs(unsigned long lc)
{
	uint32_t status = 0;
	int cc;

	report_prefix_pushf("LC %lu", lc);

	cpu_write_to_gs_regs(1);
	smp_cpu_stop(1);

	memset(&adtl_status, 0xff, sizeof(adtl_status));

	cc = smp_sigp(1, SIGP_STORE_ADDITIONAL_STATUS,
		  (unsigned long)&adtl_status | lc, &status);
	report(!cc, "CC = 0");

	report(!memcmp(&adtl_status.gs_cb, &gs_cb, sizeof(gs_cb)),
	       "additional status contents match");

	report(adtl_status_check_unmodified_fields_for_lc(lc),
	       "no write outside expected fields");

	report_prefix_pop();
}

static void test_store_adtl_status_gs(void)
{
	report_prefix_push("store additional status guarded-storage");

	if (!test_facility(133)) {
		report_skip("guarded-storage facility not installed");
		goto out;
	}

	__store_adtl_status_gs(11);
	__store_adtl_status_gs(12);

out:
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("adtl_status");

	if (smp_query_num_cpus() == 1) {
		report_skip("need at least 2 cpus for this test");
		goto done;
	}

	/* Setting up the cpu to give it a stack and lowcore */
	smp_cpu_setup(1, PSW_WITH_CUR_MASK(test_func));
	smp_cpu_stop(1);

	test_store_adtl_status_unavail();
	test_store_adtl_status_vector();
	test_store_adtl_status_gs();
	test_store_adtl_status();
	smp_cpu_destroy(1);

done:
	report_prefix_pop();
	return report_summary();
}
