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
#include <sclp.h>
#include <uv.h>

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
		/* A dword below the minimum length */
		.header.len = 0xa0,
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
	uvcb.paddr = get_ram_size() + PAGE_SIZE;
	cc = uv_call(0, (u64)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x101, "invalid memory");
	uvcb.paddr = page;
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

static struct {
	const char *name;
	uint16_t cmd;
	uint16_t len;
	int call_bit;
} invalid_cmds[] = {
	{ "bogus", 0x4242, sizeof(struct uv_cb_header), -1 },
	{ "init", UVC_CMD_INIT_UV, sizeof(struct uv_cb_init), BIT_UVC_CMD_INIT_UV },
	{ "create conf", UVC_CMD_CREATE_SEC_CONF, sizeof(struct uv_cb_cgc), BIT_UVC_CMD_CREATE_SEC_CONF },
	{ "destroy conf", UVC_CMD_DESTROY_SEC_CONF, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_DESTROY_SEC_CONF },
	{ "create cpu", UVC_CMD_CREATE_SEC_CPU, sizeof(struct uv_cb_csc), BIT_UVC_CMD_CREATE_SEC_CPU },
	{ "destroy cpu", UVC_CMD_DESTROY_SEC_CPU, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_DESTROY_SEC_CPU },
	{ "conv to", UVC_CMD_CONV_TO_SEC_STOR, sizeof(struct uv_cb_cts), BIT_UVC_CMD_CONV_TO_SEC_STOR },
	{ "conv from", UVC_CMD_CONV_FROM_SEC_STOR, sizeof(struct uv_cb_cfs), BIT_UVC_CMD_CONV_FROM_SEC_STOR },
	{ "set sec conf", UVC_CMD_SET_SEC_CONF_PARAMS, sizeof(struct uv_cb_ssc), BIT_UVC_CMD_SET_SEC_PARMS },
	{ "unpack", UVC_CMD_UNPACK_IMG, sizeof(struct uv_cb_unp), BIT_UVC_CMD_UNPACK_IMG },
	{ "verify", UVC_CMD_VERIFY_IMG, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_VERIFY_IMG },
	{ "cpu reset", UVC_CMD_CPU_RESET, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_CPU_RESET },
	{ "cpu initial reset", UVC_CMD_CPU_RESET_INITIAL, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_CPU_RESET_INITIAL },
	{ "conf clear reset", UVC_CMD_PERF_CONF_CLEAR_RESET, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_PREPARE_CLEAR_RESET },
	{ "cpu clear reset", UVC_CMD_CPU_RESET_CLEAR, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_CPU_PERFORM_CLEAR_RESET },
	{ "cpu set state", UVC_CMD_CPU_SET_STATE, sizeof(struct uv_cb_cpu_set_state), BIT_UVC_CMD_CPU_SET_STATE },
	{ "pin shared", UVC_CMD_PIN_PAGE_SHARED, sizeof(struct uv_cb_cfs), BIT_UVC_CMD_PIN_PAGE_SHARED },
	{ "unpin shared", UVC_CMD_UNPIN_PAGE_SHARED, sizeof(struct uv_cb_cts), BIT_UVC_CMD_UNPIN_PAGE_SHARED },
	{ NULL, 0, 0 },
};

static void test_invalid(void)
{
	struct uv_cb_header *hdr = (void *)page;
	int cc, i;

	report_prefix_push("invalid");
	for (i = 0; invalid_cmds[i].name; i++) {
		hdr->cmd = invalid_cmds[i].cmd;
		hdr->len = invalid_cmds[i].len;
		cc = uv_call(0, (u64)hdr);
		report(cc == 1 && hdr->rc == UVC_RC_INV_CMD &&
		       (invalid_cmds[i].call_bit == -1 || !uv_query_test_call(invalid_cmds[i].call_bit)),
		       "%s", invalid_cmds[i].name);
	}
	report_prefix_pop();
}

int main(void)
{
	bool has_uvc = test_facility(158);

	report_prefix_push("uvc");
	if (!has_uvc) {
		report_skip("Ultravisor call facility is not available");
		goto done;
	}

	if (!uv_os_is_guest()) {
		report_skip("Not a protected guest");
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
