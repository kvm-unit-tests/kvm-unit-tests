/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PV virtualization interception tests for diagnose instructions.
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <snippet.h>
#include <pv_icptdata.h>
#include <sie.h>
#include <sclp.h>
#include <asm/facility.h>

static struct vm vm;

static void test_diag_500(void)
{
	extern const char SNIPPET_NAME_START(asm, pv_diag_500)[];
	extern const char SNIPPET_NAME_END(asm, pv_diag_500)[];
	extern const char SNIPPET_HDR_START(asm, pv_diag_500)[];
	extern const char SNIPPET_HDR_END(asm, pv_diag_500)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_diag_500);
	int size_gbin = SNIPPET_LEN(asm, pv_diag_500);

	report_prefix_push("diag 0x500");

	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_diag_500),
			SNIPPET_HDR_START(asm, pv_diag_500),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x500),
	       "intercept values");
	report(vm.save_area.guest.grs[1] == 1 &&
	       vm.save_area.guest.grs[2] == 2 &&
	       vm.save_area.guest.grs[3] == 3 &&
	       vm.save_area.guest.grs[4] == 4,
	       "register values");
	/*
	 * Check if we can inject a PGM operand which we are always
	 * allowed to do after a diag500 exit.
	 */
	vm.sblk->iictl = IICTL_CODE_OPERAND;
	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x9c) &&
	       vm.save_area.guest.grs[0] == PGM_INT_CODE_OPERAND,
	       "operand exception");

	/*
	 * Check if we can inject a PGM specification which we are always
	 * allowed to do after a diag500 exit.
	 */
	sie(&vm);
	vm.sblk->iictl = IICTL_CODE_SPECIFICATION;
	/* Inject PGM, next exit should be 9c */
	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x9c) &&
	       vm.save_area.guest.grs[0] == PGM_INT_CODE_SPECIFICATION,
	       "specification exception");

	/* No need for cleanup, just tear down the VM */
	uv_destroy_guest(&vm);

	report_prefix_pop();
}


static void test_diag_288(void)
{
	extern const char SNIPPET_NAME_START(asm, pv_diag_288)[];
	extern const char SNIPPET_NAME_END(asm, pv_diag_288)[];
	extern const char SNIPPET_HDR_START(asm, pv_diag_288)[];
	extern const char SNIPPET_HDR_END(asm, pv_diag_288)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_diag_288);
	int size_gbin = SNIPPET_LEN(asm, pv_diag_288);

	report_prefix_push("diag 0x288");

	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_diag_288),
			SNIPPET_HDR_START(asm, pv_diag_288),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PV_INSTR && vm.sblk->ipa == 0x8302 &&
	       vm.sblk->ipb == 0x50000000 && vm.save_area.guest.grs[5] == 0x288,
	       "intercept values");
	report(vm.save_area.guest.grs[0] == 1 &&
	       vm.save_area.guest.grs[1] == 2 &&
	       vm.save_area.guest.grs[2] == 3,
	       "register values");

	/*
	 * Check if we can inject a PGM spec which we are always
	 * allowed to do after a diag288 exit.
	 */
	vm.sblk->iictl = IICTL_CODE_SPECIFICATION;
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PV_NOTIFY && vm.sblk->ipa == 0x8302 &&
	       vm.sblk->ipb == 0x50000000 && vm.save_area.guest.grs[5] == 0x9c
	       && vm.save_area.guest.grs[0] == PGM_INT_CODE_SPECIFICATION,
	       "specification exception");

	/* No need for cleanup, just tear down the VM */
	uv_destroy_guest(&vm);

	report_prefix_pop();
}

static void test_diag_yield(void)
{
	extern const char SNIPPET_NAME_START(asm, pv_diag_yield)[];
	extern const char SNIPPET_NAME_END(asm, pv_diag_yield)[];
	extern const char SNIPPET_HDR_START(asm, pv_diag_yield)[];
	extern const char SNIPPET_HDR_END(asm, pv_diag_yield)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_diag_yield);
	int size_gbin = SNIPPET_LEN(asm, pv_diag_yield);

	report_prefix_push("diag yield");

	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_diag_yield),
			SNIPPET_HDR_START(asm, pv_diag_yield),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	/* 0x44 */
	report_prefix_push("0x44");
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PV_NOTIFY && vm.sblk->ipa == 0x8302 &&
	       vm.sblk->ipb == 0x50000000 && vm.save_area.guest.grs[5] == 0x44,
	       "intercept values");
	report_prefix_pop();

	/* 0x9c */
	report_prefix_push("0x9c");
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PV_NOTIFY && vm.sblk->ipa == 0x8302 &&
	       vm.sblk->ipb == 0x50000000 && vm.save_area.guest.grs[5] == 0x9c,
	       "intercept values");
	report(vm.save_area.guest.grs[0] == 42, "r1 correct");
	report_prefix_pop();

	uv_destroy_guest(&vm);
	report_prefix_pop();
}


int main(void)
{
	report_prefix_push("pv-diags");
	if (!uv_host_requirement_checks())
		goto done;

	uv_setup_asces();
	snippet_setup_guest(&vm, true);
	test_diag_yield();
	test_diag_288();
	test_diag_500();
	sie_guest_destroy(&vm);

done:
	report_prefix_pop();
	return report_summary();
}
