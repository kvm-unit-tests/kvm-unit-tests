/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PV virtualization interception tests for intercepts that are not
 * caused by an instruction.
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <sie.h>
#include <smp.h>
#include <sclp.h>
#include <snippet.h>
#include <pv_icptdata.h>
#include <asm/facility.h>
#include <asm/barrier.h>
#include <asm/sigp.h>
#include <asm/uv.h>
#include <asm/time.h>

static struct vm vm, vm2;

/*
 * The hypervisor should not be able to decrease the cpu timer by an
 * amount that is higher than the amount of time spent outside of
 * SIE.
 *
 * Warning: A lot of things influence time so decreasing the timer by
 * a more significant amount than the difference to have a safety
 * margin is advised.
 */
static void test_validity_timing(void)
{
	extern const char SNIPPET_NAME_START(asm, pv_icpt_vir_timing)[];
	extern const char SNIPPET_NAME_END(asm, pv_icpt_vir_timing)[];
	extern const char SNIPPET_HDR_START(asm, pv_icpt_vir_timing)[];
	extern const char SNIPPET_HDR_END(asm, pv_icpt_vir_timing)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_icpt_vir_timing);
	int size_gbin = SNIPPET_LEN(asm, pv_icpt_vir_timing);
	uint64_t time_exit, time_entry, tmp;

	report_prefix_push("manipulated cpu time");
	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_icpt_vir_timing),
			SNIPPET_HDR_START(asm, pv_icpt_vir_timing),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x44), "spt done");
	stck(&time_exit);
	tmp = vm.sblk->cputm;
	mb();

	/* Cpu timer counts down so adding a ms should lead to a validity */
	vm.sblk->cputm += S390_CLOCK_SHIFT_US * 1000;
	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity entry cput > exit cput");
	vm.sblk->cputm = tmp;

	/*
	 * We are not allowed to decrement the timer more than the
	 * time spent outside of SIE
	 */
	stck(&time_entry);
	vm.sblk->cputm -= (time_entry - time_exit) + S390_CLOCK_SHIFT_US * 1000;
	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity entry cput < time spent outside SIE");
	vm.sblk->cputm = tmp;

	uv_destroy_guest(&vm);
	report_prefix_pop();
}

static void run_loop(void)
{
	sie(&vm);
	sigp_retry(stap(), SIGP_STOP, 0, NULL);
}

static void test_validity_already_running(void)
{
	extern const char SNIPPET_NAME_START(asm, loop)[];
	extern const char SNIPPET_NAME_END(asm, loop)[];
	extern const char SNIPPET_HDR_START(asm, loop)[];
	extern const char SNIPPET_HDR_END(asm, loop)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, loop);
	int size_gbin = SNIPPET_LEN(asm, loop);
	struct psw psw = {
		.mask = PSW_MASK_64,
		.addr = (uint64_t)run_loop,
	};

	report_prefix_push("already running");
	if (smp_query_num_cpus() < 3) {
		report_skip("need at least 3 cpus for this test");
		goto out;
	}

	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, loop),
			SNIPPET_HDR_START(asm, loop),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	smp_cpu_setup(1, psw);
	sie_expect_validity(&vm);
	smp_cpu_setup(2, psw);
	while (vm.sblk->icptcode != ICPT_VALIDITY) {
		mb();
	}

	/*
	 * One cpu will enter SIE and one will receive the validity.
	 * We rely on the expectation that the cpu in SIE won't exit
	 * until we had a chance to observe the validity as the exit
	 * would overwrite the validity.
	 *
	 * In general that expectation is valid but HW/FW can in
	 * theory still exit to handle their interrupts.
	 */
	report(uv_validity_check(&vm), "validity");
	smp_cpu_stop(1);
	smp_cpu_stop(2);
	uv_destroy_guest(&vm);

out:
	report_prefix_pop();
}

/* Tests if a vcpu handle from another configuration results in a validity intercept. */
static void test_validity_handle_not_in_config(void)
{
	extern const char SNIPPET_NAME_START(asm, icpt_loop)[];
	extern const char SNIPPET_NAME_END(asm, icpt_loop)[];
	extern const char SNIPPET_HDR_START(asm, icpt_loop)[];
	extern const char SNIPPET_HDR_END(asm, icpt_loop)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, icpt_loop);
	int size_gbin = SNIPPET_LEN(asm, icpt_loop);

	report_prefix_push("handle not in config");
	/* Setup our primary vm */
	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, icpt_loop),
			SNIPPET_HDR_START(asm, icpt_loop),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	/* Setup secondary vm */
	snippet_setup_guest(&vm2, true);
	snippet_pv_init(&vm2, SNIPPET_NAME_START(asm, icpt_loop),
			SNIPPET_HDR_START(asm, icpt_loop),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	vm.sblk->pv_handle_cpu = vm2.sblk->pv_handle_cpu;
	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "switched cpu handle");
	vm.sblk->pv_handle_cpu = vm.uv.vcpu_handle;

	vm.sblk->pv_handle_config = vm2.uv.vm_handle;
	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "switched configuration handle");
	vm.sblk->pv_handle_config = vm.uv.vm_handle;

	/* Destroy the second vm, since we don't need it for further tests */
	uv_destroy_guest(&vm2);
	sie_guest_destroy(&vm2);

	uv_destroy_guest(&vm);
	report_prefix_pop();
}

/* Tests if a wrong vm or vcpu handle results in a validity intercept. */
static void test_validity_seid(void)
{
	extern const char SNIPPET_NAME_START(asm, icpt_loop)[];
	extern const char SNIPPET_NAME_END(asm, icpt_loop)[];
	extern const char SNIPPET_HDR_START(asm, icpt_loop)[];
	extern const char SNIPPET_HDR_END(asm, icpt_loop)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, icpt_loop);
	int size_gbin = SNIPPET_LEN(asm, icpt_loop);
	int fails = 0;
	int i;

	report_prefix_push("handles");
	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, icpt_loop),
			SNIPPET_HDR_START(asm, icpt_loop),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	for (i = 0; i < 64; i++) {
		vm.sblk->pv_handle_config ^= 1UL << i;
		sie_expect_validity(&vm);
		sie(&vm);
		if (!uv_validity_check(&vm)) {
			report_fail("SIE accepted wrong VM SEID, changed bit %d",
				    63 - i);
			fails++;
		}
		vm.sblk->pv_handle_config ^= 1UL << i;
	}
	report(!fails, "No wrong vm handle accepted");

	fails = 0;
	for (i = 0; i < 64; i++) {
		vm.sblk->pv_handle_cpu ^= 1UL << i;
		sie_expect_validity(&vm);
		sie(&vm);
		if (!uv_validity_check(&vm)) {
			report_fail("SIE accepted wrong CPU SEID, changed bit %d",
				    63 - i);
			fails++;
		}
		vm.sblk->pv_handle_cpu ^= 1UL << i;
	}
	report(!fails, "No wrong cpu handle accepted");

	uv_destroy_guest(&vm);
	report_prefix_pop();
}

/*
 * Tests if we get a validity intercept if the CR1 asce at SIE entry
 * is not the same as the one given at the UV creation of the VM.
 */
static void test_validity_asce(void)
{
	extern const char SNIPPET_NAME_START(asm, pv_icpt_112)[];
	extern const char SNIPPET_NAME_END(asm, pv_icpt_112)[];
	extern const char SNIPPET_HDR_START(asm, pv_icpt_112)[];
	extern const char SNIPPET_HDR_END(asm, pv_icpt_112)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_icpt_112);
	int size_gbin = SNIPPET_LEN(asm, pv_icpt_112);
	uint64_t asce_old, asce_new;
	void *pgd_new, *pgd_old;

	report_prefix_push("asce");
	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_icpt_112),
			SNIPPET_HDR_START(asm, pv_icpt_112),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	asce_old = vm.save_area.guest.asce;
	pgd_new = memalign_pages_flags(PAGE_SIZE, PAGE_SIZE * 4, 0);
	pgd_old = (void *)(asce_old & PAGE_MASK);

	/* Copy the contents of the top most table */
	memcpy(pgd_new, pgd_old, PAGE_SIZE * 4);

	/* Create the replacement ASCE */
	asce_new = __pa(pgd_new) | ASCE_DT_REGION1 | REGION_TABLE_LENGTH | ASCE_P;
	vm.save_area.guest.asce = asce_new;

	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "wrong CR1 validity");

	/* Restore the old ASCE */
	vm.save_area.guest.asce = asce_old;

	/* Try if we can still do an entry with the correct asce */
	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x44), "re-entry with valid CR1");
	uv_destroy_guest(&vm);
	free_pages(pgd_new);
	report_prefix_pop();
}

static void run_icpt_122_tests(unsigned long lc_off)
{
	uv_export(vm.sblk->mso + lc_off);
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PV_PREF, "Intercept 112 for page 0");
	uv_import(vm.uv.vm_handle, vm.sblk->mso + lc_off);

	uv_export(vm.sblk->mso + lc_off + PAGE_SIZE);
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PV_PREF, "Intercept 112 for page 1");
	uv_import(vm.uv.vm_handle, vm.sblk->mso + lc_off + PAGE_SIZE);
}

static void run_icpt_122_tests_prefix(unsigned long prefix)
{
	uint32_t *ptr = 0;

	report_prefix_pushf("0x%lx", prefix);
	report_prefix_push("unshared");
	run_icpt_122_tests(prefix);
	report_prefix_pop();

	/*
	 * Guest will share the lowcore and we need to check if that
	 * makes a difference (which it should not).
	 */
	report_prefix_push("shared");

	sie(&vm);
	/* Guest indicates that it has been setup via the diag 0x44 */
	assert(pv_icptdata_check_diag(&vm, 0x44));
	/* If the pages have not been shared these writes will cause exceptions */
	ptr = (uint32_t *)prefix;
	WRITE_ONCE(ptr, 0);
	ptr = (uint32_t *)(prefix + offsetof(struct lowcore, ars_sa[0]));
	WRITE_ONCE(ptr, 0);

	run_icpt_122_tests(prefix);

	/* shared*/
	report_prefix_pop();
	/* prefix hex value */
	report_prefix_pop();
}

static void test_icpt_112(void)
{
	extern const char SNIPPET_NAME_START(asm, pv_icpt_112)[];
	extern const char SNIPPET_NAME_END(asm, pv_icpt_112)[];
	extern const char SNIPPET_HDR_START(asm, pv_icpt_112)[];
	extern const char SNIPPET_HDR_END(asm, pv_icpt_112)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_icpt_112);
	int size_gbin = SNIPPET_LEN(asm, pv_icpt_112);

	unsigned long lc_off = 0;

	report_prefix_push("prefix");

	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_icpt_112),
			SNIPPET_HDR_START(asm, pv_icpt_112),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	/* Setup of the guest's state for 0x0 prefix */
	sie(&vm);
	assert(pv_icptdata_check_diag(&vm, 0x44));

	/* Test on standard 0x0 prefix */
	run_icpt_122_tests_prefix(0);

	/* Setup of the guest's state for 0x8000 prefix */
	lc_off = 0x8000;
	uv_import(vm.uv.vm_handle, vm.sblk->mso + lc_off);
	uv_import(vm.uv.vm_handle, vm.sblk->mso + lc_off + PAGE_SIZE);
	/* Guest will set prefix to 0x8000 */
	sie(&vm);
	/* SPX generates a PV instruction notification */
	assert(vm.sblk->icptcode == ICPT_PV_NOTIFY && vm.sblk->ipa == 0xb210);
	assert(*(u32 *)vm.sblk->sidad == 0x8000);

	/* Test on 0x8000 prefix */
	run_icpt_122_tests_prefix(0x8000);

	/* Try a re-entry after everything has been imported again */
	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x9c) &&
	       vm.save_area.guest.grs[0] == 42,
	       "re-entry successful");
	report_prefix_pop();
	uv_destroy_guest(&vm);
}

int main(void)
{
	report_prefix_push("pv-icpts");
	if (!uv_host_requirement_checks())
		goto done;

	snippet_setup_guest(&vm, true);
	test_icpt_112();
	test_validity_asce();
	test_validity_seid();
	test_validity_handle_not_in_config();
	test_validity_already_running();
	test_validity_timing();
	sie_guest_destroy(&vm);

done:
	report_prefix_pop();
	return report_summary();
}
