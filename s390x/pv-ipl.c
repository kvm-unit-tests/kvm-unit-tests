/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PV diagnose 308 (IPL) tests
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <sie.h>
#include <sclp.h>
#include <snippet.h>
#include <pv_icptdata.h>
#include <asm/facility.h>
#include <asm/uv.h>

static struct vm vm;

static void test_diag_308(int subcode)
{
	extern const char SNIPPET_NAME_START(asm, pv_diag_308)[];
	extern const char SNIPPET_NAME_END(asm, pv_diag_308)[];
	extern const char SNIPPET_HDR_START(asm, pv_diag_308)[];
	extern const char SNIPPET_HDR_END(asm, pv_diag_308)[];
	int size_hdr = SNIPPET_HDR_LEN(asm, pv_diag_308);
	int size_gbin = SNIPPET_LEN(asm, pv_diag_308);
	uint16_t rc, rrc;
	int cc;

	report_prefix_pushf("subcode %d", subcode);
	snippet_pv_init(&vm, SNIPPET_NAME_START(asm, pv_diag_308),
			SNIPPET_HDR_START(asm, pv_diag_308),
			size_gbin, size_hdr, SNIPPET_UNPACK_OFF);

	/* First exit is a diag 0x500 */
	sie(&vm);
	assert(pv_icptdata_check_diag(&vm, 0x500));

	/*
	 * The snippet asked us for the subcode and we answer by
	 * putting the value in gr2.
	 * SIE will copy gr2 to the guest
	 */
	vm.save_area.guest.grs[2] = subcode;

	/* Continue after diag 0x500, next icpt should be the 0x308 */
	sie(&vm);
	assert(pv_icptdata_check_diag(&vm, 0x308));
	assert(vm.save_area.guest.grs[2] == subcode);

	/*
	 * We need to perform several UV calls to emulate the subcode
	 * 0/1. Failing to do that should result in a validity.
	 *
	 * - Mark all cpus as stopped
	 * - Unshare all memory
	 * - Prepare the reset
	 * - Reset the cpus
	 * - Load the reset PSW
	 */
	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity, no action");

	/* Mark the CPU as stopped so we can unshare and reset */
	cc = uv_set_cpu_state(vm.sblk->pv_handle_cpu, PV_CPU_STATE_STP);
	report(!cc, "Set cpu stopped");

	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity, stopped");

	/* Unshare all memory */
	cc = uv_cmd_nodata(vm.sblk->pv_handle_config,
			   UVC_CMD_SET_UNSHARED_ALL, &rc, &rrc);
	report(cc == 0 && rc == 1, "Unshare all");

	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity, stopped, unshared");

	/* Prepare the CPU reset */
	cc = uv_cmd_nodata(vm.sblk->pv_handle_config,
			   UVC_CMD_PREPARE_RESET, &rc, &rrc);
	report(cc == 0 && rc == 1, "Prepare reset call");

	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity, stopped, unshared, prep reset");

	/*
	 * Do the reset on the initiating cpu
	 *
	 * Reset clear for subcode 0
	 * Reset initial for subcode 1
	 */
	if (subcode == 0) {
		cc = uv_cmd_nodata(vm.sblk->pv_handle_cpu,
				   UVC_CMD_CPU_RESET_CLEAR, &rc, &rrc);
		report(cc == 0 && rc == 1, "Clear reset cpu");
	} else {
		cc = uv_cmd_nodata(vm.sblk->pv_handle_cpu,
				   UVC_CMD_CPU_RESET_INITIAL, &rc, &rrc);
		report(cc == 0 && rc == 1, "Initial reset cpu");
	}

	sie_expect_validity(&vm);
	sie(&vm);
	report(uv_validity_check(&vm), "validity, stopped, unshared, prep reset, cpu reset");

	/* Load the PSW from 0x0 */
	cc = uv_set_cpu_state(vm.sblk->pv_handle_cpu, PV_CPU_STATE_OPR_LOAD);
	report(!cc, "Set cpu load");

	/*
	 * Check if we executed the iaddr of the reset PSW, we should
	 * see a diagnose 0x9c PV instruction notification.
	 */
	sie(&vm);
	report(pv_icptdata_check_diag(&vm, 0x9c) &&
	       vm.save_area.guest.grs[0] == 42,
	       "continue after load");

	uv_destroy_guest(&vm);
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("uv-sie");
	if (!uv_host_requirement_checks())
		goto done;

	snippet_setup_guest(&vm, true);
	test_diag_308(0);
	test_diag_308(1);
	sie_guest_destroy(&vm);

done:
	report_prefix_pop();
	return report_summary();
}
