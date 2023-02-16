/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Migration Test for s390x
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <migrate.h>
#include <asm/arch_def.h>
#include <asm/vector.h>
#include <asm/barrier.h>
#include <asm/facility.h>
#include <gs.h>
#include <bitops.h>
#include <smp.h>

static struct gs_cb gs_cb;
static struct gs_epl gs_epl;

/* set by CPU1 to signal it has completed */
static int flag_thread_complete;
/* set by CPU0 to signal migration has completed */
static int flag_migration_complete;

static void write_gs_regs(void)
{
	const unsigned long gs_area = 0x2000000;
	const unsigned long gsc = 25; /* align = 32 M, section size = 512K */

	gs_cb.gsd = gs_area | gsc;
	gs_cb.gssm = 0xfeedc0ffe;
	gs_cb.gs_epl_a = (uint64_t) &gs_epl;

	load_gs_cb(&gs_cb);
}

static void check_gs_regs(void)
{
	struct gs_cb gs_cb_after_migration;

	store_gs_cb(&gs_cb_after_migration);

	report_prefix_push("guarded-storage registers");

	report(gs_cb_after_migration.gsd == gs_cb.gsd, "gsd matches");
	report(gs_cb_after_migration.gssm == gs_cb.gssm, "gssm matches");
	report(gs_cb_after_migration.gs_epl_a == gs_cb.gs_epl_a, "gs_epl_a matches");

	report_prefix_pop();
}

static bool have_vector_facility(void)
{
	return test_facility(129);
}

static bool have_guarded_storage_facility(void)
{
	return test_facility(133);
}

static void test_func(void)
{
	uint8_t expected_vec_contents[VEC_REGISTER_NUM][VEC_REGISTER_SIZE];
	uint8_t actual_vec_contents[VEC_REGISTER_NUM][VEC_REGISTER_SIZE];
	uint8_t *vec_reg;
	int i;
	int vec_result = 0;

	if (have_guarded_storage_facility()) {
		ctl_set_bit(2, CTL2_GUARDED_STORAGE);

		write_gs_regs();
	}

	if (have_vector_facility()) {
		for (i = 0; i < VEC_REGISTER_NUM; i++) {
			vec_reg = &expected_vec_contents[i][0];
			/* i+1 to avoid zero content */
			memset(vec_reg, i + 1, VEC_REGISTER_SIZE);
		}

		ctl_set_bit(0, CTL0_VECTOR);

		/*
		 * It is important loading the vector/floating point registers and
		 * comparing their contents occurs in the same inline assembly block.
		 * Otherwise, the compiler is allowed to re-use the registers for
		 * something else in between.
		 * For this very reason, this also runs on a second CPU, so all the
		 * complex console stuff can be done in C on the first CPU and here we
		 * just need to wait for it to set the flag.
		 */
		asm inline(
			"	.machine z13\n"
			/* load vector registers: vlm handles at most 16 registers at a time */
			"	vlm 0,15, 0(%[expected_vec_reg])\n"
			"	vlm 16,31, 256(%[expected_vec_reg])\n"
			/* inform CPU0 we are done, it will request migration */
			"	mvhi %[flag_thread_complete], 1\n"
			/* wait for migration to finish */
			"0:	clfhsi %[flag_migration_complete], 1\n"
			"	jnz 0b\n"
			/*
			 * store vector register contents in actual_vec_reg: vstm
			 * handles at most 16 registers at a time
			 */
			"	vstm 0,15, 0(%[actual_vec_reg])\n"
			"	vstm 16,31, 256(%[actual_vec_reg])\n"
			/*
			 * compare the contents in expected_vec_reg with actual_vec_reg:
			 * clc handles at most 256 bytes at a time
			 */
			"	clc 0(256, %[expected_vec_reg]), 0(%[actual_vec_reg])\n"
			"	jnz 1f\n"
			"	clc 256(256, %[expected_vec_reg]), 256(%[actual_vec_reg])\n"
			"	jnz 1f\n"
			/* success */
			"	mvhi %[vec_result], 1\n"
			"1:"
			:
			: [expected_vec_reg] "a"(expected_vec_contents),
			  [actual_vec_reg] "a"(actual_vec_contents),
			  [flag_thread_complete] "Q"(flag_thread_complete),
			  [flag_migration_complete] "Q"(flag_migration_complete),
			  [vec_result] "Q"(vec_result)
			: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
			  "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18",
			  "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27",
			  "v28", "v29", "v30", "v31", "cc", "memory"
		);

		report(vec_result, "vector contents match");

		report(stctg(0) & BIT(CTL0_VECTOR), "ctl0 vector bit set");

		ctl_clear_bit(0, CTL0_VECTOR);
	} else {
		flag_thread_complete = 1;
		while(!flag_migration_complete)
			mb();
	}

	report_pass("Migrated");

	if (have_guarded_storage_facility()) {
		check_gs_regs();

		report(stctg(2) & BIT(CTL2_GUARDED_STORAGE), "ctl2 guarded-storage bit set");

		ctl_clear_bit(2, CTL2_GUARDED_STORAGE);
	}

	flag_thread_complete = 1;
}

int main(void)
{
	/* don't say migrate here otherwise we will migrate right away */
	report_prefix_push("migration");

	if (smp_query_num_cpus() == 1) {
		report_skip("need at least 2 cpus for this test");
		goto done;
	}

	/* Second CPU does the actual tests */
	smp_cpu_setup(1, PSW_WITH_CUR_MASK(test_func));

	/* wait for thread setup */
	while(!flag_thread_complete)
		mb();
	flag_thread_complete = 0;

	migrate_once();

	flag_migration_complete = 1;

	/* wait for thread to complete assertions */
	while(!flag_thread_complete)
		mb();

	smp_cpu_destroy(1);

done:
	report_prefix_pop();
	return report_summary();
}
