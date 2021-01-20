/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Guest Ultravisor Call tests
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */

#include <libcflat.h>
#include <alloc_page.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/facility.h>
#include <asm/uv.h>

static unsigned long page;

static void test_priv(void)
{
	struct uv_cb_header uvcb = {};

	report_prefix_push("privileged");

	report_prefix_push("query");
	uvcb.cmd = UVC_CMD_QUI;
	uvcb.len = sizeof(struct uv_cb_qui);
	expect_pgm_int();
	enter_pstate();
	uv_call_once(0, (u64)&uvcb);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	report_prefix_push("share");
	uvcb.cmd = UVC_CMD_SET_SHARED_ACCESS;
	uvcb.len = sizeof(struct uv_cb_share);
	expect_pgm_int();
	enter_pstate();
	uv_call_once(0, (u64)&uvcb);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	report_prefix_push("unshare");
	uvcb.cmd = UVC_CMD_REMOVE_SHARED_ACCESS;
	uvcb.len = sizeof(struct uv_cb_share);
	expect_pgm_int();
	enter_pstate();
	uv_call_once(0, (u64)&uvcb);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();

	report_prefix_pop();
}

static void test_query(void)
{
	struct uv_cb_qui uvcb = {
		.header.cmd = UVC_CMD_QUI,
		.header.len = sizeof(uvcb) - 8,
	};
	int cc;

	report_prefix_push("query");
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 1 && uvcb.header.rc == UVC_RC_INV_LEN, "length");

	uvcb.header.len = sizeof(uvcb);
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 0 && uvcb.header.rc == UVC_RC_EXECUTED, "successful query");

	/*
	 * These bits have been introduced with the very first
	 * Ultravisor version and are expected to always be available
	 * because they are basic building blocks.
	 */
	report(test_bit_inv(BIT_UVC_CMD_QUI, &uvcb.inst_calls_list[0]),
	       "query indicated");
	report(test_bit_inv(BIT_UVC_CMD_SET_SHARED_ACCESS, &uvcb.inst_calls_list[0]),
	       "share indicated");
	report(test_bit_inv(BIT_UVC_CMD_REMOVE_SHARED_ACCESS, &uvcb.inst_calls_list[0]),
	       "unshare indicated");
	report_prefix_pop();
}

static void test_sharing(void)
{
	struct uv_cb_share uvcb = {
		.header.cmd = UVC_CMD_SET_SHARED_ACCESS,
		.header.len = sizeof(uvcb) - 8,
		.paddr = page,
	};
	int cc;

	report_prefix_push("share");
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 1 && uvcb.header.rc == UVC_RC_INV_LEN, "length");
	uvcb.header.len = sizeof(uvcb);
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 0 && uvcb.header.rc == UVC_RC_EXECUTED, "share");
	report_prefix_pop();

	report_prefix_push("unshare");
	uvcb.header.cmd = UVC_CMD_REMOVE_SHARED_ACCESS;
	uvcb.header.len -= 8;
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 1 && uvcb.header.rc == UVC_RC_INV_LEN, "length");
	uvcb.header.len = sizeof(uvcb);
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 0 && uvcb.header.rc == UVC_RC_EXECUTED, "unshare");
	report_prefix_pop();

	report_prefix_pop();
}

static void test_invalid(void)
{
	struct uv_cb_header uvcb = {
		.len = 16,
		.cmd = 0x4242,
	};
	int cc;

	cc = uv_call(0, (u64)&uvcb);
	report(cc == 1 && uvcb.rc == UVC_RC_INV_CMD, "invalid command");
}

int main(void)
{
	bool has_uvc = test_facility(158);

	report_prefix_push("uvc");
	if (!has_uvc) {
		report_skip("Ultravisor call facility is not available");
		goto done;
	}

	page = (unsigned long)alloc_page();
	test_priv();
	test_invalid();
	test_query();
	test_sharing();
	free_page((void *)page);
done:
	report_prefix_pop();
	return report_summary();
}
