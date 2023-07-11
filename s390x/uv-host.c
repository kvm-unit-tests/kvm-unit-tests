/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host Ultravisor Call tests
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */

#include <libcflat.h>
#include <hardware.h>
#include <alloc.h>
#include <vmalloc.h>
#include <sclp.h>
#include <smp.h>
#include <uv.h>
#include <snippet.h>
#include <mmu.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/facility.h>
#include <asm/pgtable.h>
#include <asm/uv.h>
#include <asm-generic/barrier.h>

static struct uv_cb_qui uvcb_qui;
static struct uv_cb_init uvcb_init;
static struct uv_cb_cgc uvcb_cgc;
static struct uv_cb_csc uvcb_csc;

extern int diag308_load_reset(u64 code);

struct cmd_list {
	const char *name;
	uint16_t cmd;
	uint16_t len;
	int call_bit;
};

static void cpu_loop(void)
{
	for (;;) {}
}

/*
 * Checks if a memory area is protected as secure memory.
 * Will return true if all pages are protected, false otherwise.
 */
static bool access_check_3d(uint8_t *access_ptr, uint64_t len)
{
	assert(!(len & ~PAGE_MASK));
	assert(!((uint64_t)access_ptr & ~PAGE_MASK));

	while (len) {
		expect_pgm_int();
		READ_ONCE(*access_ptr);
		if (clear_pgm_int() != PGM_INT_CODE_SECURE_STOR_ACCESS)
			return false;
		expect_pgm_int();
		WRITE_ONCE(*access_ptr, 42);
		if (clear_pgm_int() != PGM_INT_CODE_SECURE_STOR_ACCESS)
			return false;

		access_ptr += PAGE_SIZE;
		len -= PAGE_SIZE;
	}

	return true;
}

static struct cmd_list cmds[] = {
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
	{ "conf clear reset", UVC_CMD_PREPARE_RESET, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_PREPARE_RESET },
	{ "cpu clear reset", UVC_CMD_CPU_RESET_CLEAR, sizeof(struct uv_cb_nodata), BIT_UVC_CMD_CPU_PERFORM_CLEAR_RESET },
	{ "cpu set state", UVC_CMD_CPU_SET_STATE, sizeof(struct uv_cb_cpu_set_state), BIT_UVC_CMD_CPU_SET_STATE },
	{ "pin shared", UVC_CMD_PIN_PAGE_SHARED, sizeof(struct uv_cb_cfs), BIT_UVC_CMD_PIN_PAGE_SHARED },
	{ "unpin shared", UVC_CMD_UNPIN_PAGE_SHARED, sizeof(struct uv_cb_cts), BIT_UVC_CMD_UNPIN_PAGE_SHARED },
	{ NULL, 0, 0 },
};

static void test_i3(void)
{
	struct uv_cb_header uvcb = {
		.cmd = UVC_CMD_INIT_UV,
		.len = sizeof(struct uv_cb_init),
	};
	unsigned long r1 = 0;
	int cc;

	report_prefix_push("i3");
	expect_pgm_int();
	asm volatile(
		"0:	.insn rrf,0xB9A40000,%[r1],%[r2],4,2\n"
		"		ipm	%[cc]\n"
		"		srl	%[cc],28\n"
		: [cc] "=d" (cc)
		: [r1] "a" (r1), [r2] "a" (&uvcb)
		: "memory", "cc");
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static void test_priv(void)
{
	struct uv_cb_header uvcb = {};
	uint16_t pgm;
	int i;

	report_prefix_push("privileged");
	for (i = 0; cmds[i].name; i++) {
		expect_pgm_int();
		uvcb.cmd = cmds[i].cmd;
		uvcb.len = cmds[i].len;
		enter_pstate();
		uv_call_once(0, (uint64_t)&uvcb);
		pgm = clear_pgm_int();
		report(pgm == PGM_INT_CODE_PRIVILEGED_OPERATION, "%s", cmds[i].name);
	}
	report_prefix_pop();
}

static void test_uv_uninitialized(void)
{
	struct uv_cb_header uvcb = {};
	int i;

	report_prefix_push("uninitialized");

	for (i = 0; cmds[i].name; i++) {
		if (cmds[i].cmd == UVC_CMD_INIT_UV)
			continue;
		expect_pgm_int();
		uvcb.cmd = cmds[i].cmd;
		uvcb.len = cmds[i].len;
		uv_call_once(0, (uint64_t)&uvcb);
		report(uvcb.rc == UVC_RC_INV_STATE, "%s", cmds[i].name);
	}
	report_prefix_pop();
}

static void test_access(void)
{
	struct uv_cb_header *uvcb;
	void *pages =  alloc_pages(1);
	uint16_t pgm;
	int i;

	/* Put UVCB on second page which we will protect later */
	uvcb = pages + PAGE_SIZE;

	report_prefix_push("access");

	/*
	 * If debug is enabled info from the uv header is printed
	 * which would lead to a second exception and a test abort.
	 */
	if (UVC_ERR_DEBUG) {
		report_skip("Debug doesn't work with access tests");
		goto out;
	}

	report_prefix_push("non-crossing");
	protect_page(uvcb, PAGE_ENTRY_I);
	for (i = 0; cmds[i].name; i++) {
		expect_pgm_int();
		mb();
		uv_call_once(0, (uint64_t)uvcb);
		pgm = clear_pgm_int();
		report(pgm == PGM_INT_CODE_PAGE_TRANSLATION, "%s", cmds[i].name);
	}
	report_prefix_pop();

	report_prefix_push("crossing");
	/*
	 * Put the header into the readable page 1, everything after
	 * the header will be on the second, invalid page.
	 */
	uvcb -= 1;
	for (i = 0; cmds[i].name; i++) {
		uvcb->cmd = cmds[i].cmd;
		uvcb->len = cmds[i].len;

		expect_pgm_int();
		mb();
		uv_call_once(0, (uint64_t)uvcb);
		pgm = clear_pgm_int();
		report(pgm == PGM_INT_CODE_PAGE_TRANSLATION, "%s", cmds[i].name);
	}
	report_prefix_pop();

	uvcb += 1;
	unprotect_page(uvcb, PAGE_ENTRY_I);

out:
	free_pages(pages);
	report_prefix_pop();
}

static void test_config_destroy(void)
{
	int rc;
	struct uv_cb_nodata uvcb = {
		.header.cmd = UVC_CMD_DESTROY_SEC_CONF,
		.header.len = sizeof(uvcb),
		.handle = uvcb_cgc.guest_handle,
	};

	report_prefix_push("dsc");
	uvcb.header.len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == UVC_RC_INV_LEN,
	       "hdr invalid length");
	uvcb.header.len += 8;

	uvcb.handle += 1;
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == UVC_RC_INV_GHANDLE, "invalid handle");
	uvcb.handle -= 1;

	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 0 && uvcb.header.rc == UVC_RC_EXECUTED, "success");
	report_prefix_pop();
}

static void test_cpu_destroy(void)
{
	int rc;
	struct uv_cb_nodata uvcb = {
		.header.len = sizeof(uvcb),
		.header.cmd = UVC_CMD_DESTROY_SEC_CPU,
		.handle = uvcb_csc.cpu_handle,
	};

	report_prefix_push("dcpu");

	uvcb.header.len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == UVC_RC_INV_LEN,
	       "hdr invalid length");
	uvcb.header.len += 8;

	if (!machine_is_z15()) {
		uvcb.handle += 1;
		rc = uv_call(0, (uint64_t)&uvcb);
		report(rc == 1 && uvcb.header.rc == UVC_RC_INV_CHANDLE, "invalid handle");
		uvcb.handle -= 1;
	}

	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 0 && uvcb.header.rc == UVC_RC_EXECUTED, "success");

	report_prefix_pop();
}

static void test_set_se_header(void)
{
	struct uv_cb_ssc uvcb = {
		.header.cmd = UVC_CMD_SET_SEC_CONF_PARAMS,
		.header.len = sizeof(uvcb),
		.guest_handle = uvcb_cgc.guest_handle,
		.sec_header_origin = 0,
		.sec_header_len = 0x1000,
	};
	void *pages =  alloc_pages(1);
	void *inv;
	int rc;

	report_prefix_push("sscp");

	uvcb.header.len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == UVC_RC_INV_LEN,
	       "hdr invalid length");
	uvcb.header.len += 8;

	uvcb.guest_handle += 1;
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == UVC_RC_INV_GHANDLE, "invalid handle");
	uvcb.guest_handle -= 1;

	inv = pages + PAGE_SIZE;
	uvcb.sec_header_origin = (uint64_t)inv;
	protect_page(inv, PAGE_ENTRY_I);
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == 0x103,
	       "se hdr access exception");

	/*
	 * Shift the ptr so the first few DWORDs are accessible but
	 * the following are on an invalid page.
	 */
	uvcb.sec_header_origin -= 0x20;
	rc = uv_call(0, (uint64_t)&uvcb);
	report(rc == 1 && uvcb.header.rc == 0x103,
	       "se hdr access exception crossing");
	unprotect_page(inv, PAGE_ENTRY_I);

	free_pages(pages);
	report_prefix_pop();
}

static void test_cpu_create(void)
{
	int rc;
	unsigned long tmp;

	report_prefix_push("csc");
	uvcb_csc.header.len = sizeof(uvcb_csc);
	uvcb_csc.header.cmd = UVC_CMD_CREATE_SEC_CPU;
	uvcb_csc.guest_handle = uvcb_cgc.guest_handle;
	uvcb_csc.stor_origin = (unsigned long)memalign(PAGE_SIZE, uvcb_qui.cpu_stor_len);
	uvcb_csc.state_origin = (unsigned long)memalign(PAGE_SIZE, PAGE_SIZE);

	uvcb_csc.header.len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(uvcb_csc.header.rc == UVC_RC_INV_LEN && rc == 1 &&
	       !uvcb_csc.cpu_handle, "hdr invalid length");
	uvcb_csc.header.len += 8;

	uvcb_csc.guest_handle += 1;
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(uvcb_csc.header.rc == UVC_RC_INV_GHANDLE && rc == 1,
	       "invalid guest handle");
	uvcb_csc.guest_handle -= 1;

	uvcb_csc.num = uvcb_qui.max_guest_cpus + 1;
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(uvcb_csc.header.rc == 0x103 && rc == 1,
	       "invalid cpu #");
	uvcb_csc.num = 0;

	tmp = uvcb_csc.stor_origin;
	uvcb_csc.stor_origin = get_max_ram_size() + PAGE_SIZE;
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(uvcb_csc.header.rc == 0x105 && rc == 1,
	       "cpu stor inaccessible");
	uvcb_csc.stor_origin = tmp;

	tmp = uvcb_csc.stor_origin;
	uvcb_csc.stor_origin = 0;
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(uvcb_csc.header.rc == 0x106 && rc == 1,
	       "cpu stor in lowcore");
	uvcb_csc.stor_origin = tmp;

	tmp = uvcb_csc.state_origin;
	uvcb_csc.state_origin = get_max_ram_size() + PAGE_SIZE;
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(uvcb_csc.header.rc == 0x107 && rc == 1,
	       "SIE SD inaccessible");
	uvcb_csc.state_origin = tmp;

	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(rc == 0 && uvcb_csc.header.rc == UVC_RC_EXECUTED &&
	       uvcb_csc.cpu_handle, "success");

	rc = access_check_3d((uint8_t *)uvcb_csc.stor_origin,
			     uvcb_qui.cpu_stor_len);
	report(rc, "Storage protection");

	tmp = uvcb_csc.stor_origin;
	uvcb_csc.stor_origin = (unsigned long)memalign(PAGE_SIZE, uvcb_qui.cpu_stor_len);
	rc = uv_call(0, (uint64_t)&uvcb_csc);
	report(rc == 1 && uvcb_csc.header.rc == 0x104, "already defined");
	uvcb_csc.stor_origin = tmp;
	report_prefix_pop();
}

/*
 * If the first bit of the rc is set we need to destroy the
 * configuration before testing other create config errors.
 */
static void cgc_destroy_if_needed(struct uv_cb_cgc *uvcb)
{
	uint16_t rc, rrc;

	if (uvcb->header.rc != UVC_RC_EXECUTED &&
	    !(uvcb->header.rc & UVC_RC_DSTR_NEEDED_FLG))
		return;

	assert(uvcb->guest_handle);
	assert(!uv_cmd_nodata(uvcb->guest_handle, UVC_CMD_DESTROY_SEC_CONF,
			      &rc, &rrc));

	/* We need to zero it for the next test */
	uvcb->guest_handle = 0;
}

static bool cgc_check_data(struct uv_cb_cgc *uvcb, uint16_t rc_expected)
{
	/* This function purely checks for error rcs */
	if (uvcb->header.rc == UVC_RC_EXECUTED)
		return false;

	/*
	 * We should only receive a handle when the rc is 1 or the
	 * first bit is set.
	 */
	if (!(uvcb->header.rc & UVC_RC_DSTR_NEEDED_FLG) && uvcb->guest_handle)
		report_abort("Received a handle when we didn't expect one");

	return (uvcb->header.rc & ~UVC_RC_DSTR_NEEDED_FLG) == rc_expected;
}

static void test_config_create(void)
{
	int rc;
	unsigned long vsize, tmp;
	static struct uv_cb_cgc uvcb;

	uvcb_cgc.header.cmd = UVC_CMD_CREATE_SEC_CONF;
	uvcb_cgc.header.len = sizeof(uvcb_cgc);
	report_prefix_push("cgc");

	uvcb_cgc.guest_stor_origin = 0;
	uvcb_cgc.guest_stor_len = 42 * (1UL << 20);
	vsize = uvcb_qui.conf_base_virt_stor_len +
		((uvcb_cgc.guest_stor_len / (1UL << 20)) * uvcb_qui.conf_virt_var_stor_len);

	uvcb_cgc.conf_base_stor_origin = (uint64_t)memalign(PAGE_SIZE * 4, uvcb_qui.conf_base_phys_stor_len);
	uvcb_cgc.conf_var_stor_origin = (uint64_t)memalign(PAGE_SIZE, vsize);
	uvcb_cgc.guest_asce = (uint64_t)memalign(PAGE_SIZE, 4 * PAGE_SIZE) | ASCE_DT_SEGMENT | REGION_TABLE_LENGTH | ASCE_P;
	uvcb_cgc.guest_sca = (uint64_t)memalign(PAGE_SIZE * 4, PAGE_SIZE * 4);

	uvcb_cgc.header.len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(uvcb_cgc.header.rc == UVC_RC_INV_LEN && rc == 1 &&
	       !uvcb_cgc.guest_handle, "hdr invalid length");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.header.len += 8;

	uvcb_cgc.guest_stor_origin = uvcb_qui.max_guest_stor_addr + (1UL << 20) * 2 + 1;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x101) && rc == 1,
	       "MSO > max guest addr");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_stor_origin = 0;

	uvcb_cgc.guest_stor_origin = uvcb_qui.max_guest_stor_addr - (1UL << 20);
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x102) && rc == 1,
	       "MSO + MSL > max guest addr");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_stor_origin = 0;

	uvcb_cgc.guest_asce &= ~ASCE_P;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x105) && rc == 1,
	       "ASCE private bit missing");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_asce |= ASCE_P;

	uvcb_cgc.guest_asce |= 0x20;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x105) && rc == 1,
	       "ASCE bit 58 set");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_asce &= ~0x20;

	tmp = uvcb_cgc.conf_base_stor_origin;
	uvcb_cgc.conf_base_stor_origin = get_max_ram_size() + 8;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x108) && rc == 1,
	       "base storage origin > available memory");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.conf_base_stor_origin = tmp;

	tmp = uvcb_cgc.conf_base_stor_origin;
	uvcb_cgc.conf_base_stor_origin = 0x1000;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x109) && rc == 1,
	       "base storage origin contains lowcore %x",  uvcb_cgc.header.rc);
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.conf_base_stor_origin = tmp;

	tmp = uvcb_cgc.guest_sca;
	uvcb_cgc.guest_sca = 0;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x10c) && rc == 1,
	       "sca == 0");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_sca = tmp;

	tmp = uvcb_cgc.guest_sca;
	uvcb_cgc.guest_sca = get_max_ram_size() + PAGE_SIZE * 4;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(cgc_check_data(&uvcb_cgc, 0x10d) && rc == 1,
	       "sca inaccessible");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_sca = tmp;

	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(rc == 0 && uvcb_cgc.header.rc == UVC_RC_EXECUTED, "successful");

	rc = access_check_3d((uint8_t *)uvcb_cgc.conf_base_stor_origin,
			     uvcb_qui.conf_base_phys_stor_len);
	report(rc, "Base storage protection");

	rc = access_check_3d((uint8_t *)uvcb_cgc.conf_var_stor_origin, vsize);
	report(rc, "Variable storage protection");

	uvcb_cgc.header.rc = 0;
	uvcb_cgc.header.rrc = 0;
	tmp = uvcb_cgc.guest_handle;
	uvcb_cgc.guest_handle = 0;
	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	report(uvcb_cgc.header.rc >= 0x100 && rc == 1, "reuse uvcb");
	cgc_destroy_if_needed(&uvcb_cgc);
	uvcb_cgc.guest_handle = tmp;

	/* Copy over most data from uvcb_cgc, so we have the ASCE that was used. */
	memcpy(&uvcb, &uvcb_cgc, sizeof(uvcb));

	/* Reset the header and handle */
	uvcb.header.rc = 0;
	uvcb.header.rrc = 0;
	uvcb.guest_handle = 0;

	/* Use new storage areas. */
	uvcb.conf_base_stor_origin = (uint64_t)memalign(PAGE_SIZE * 4, uvcb_qui.conf_base_phys_stor_len);
	uvcb.conf_var_stor_origin = (uint64_t)memalign(PAGE_SIZE, vsize);

	rc = uv_call(0, (uint64_t)&uvcb);
	report(uvcb.header.rc >= 0x104 && rc == 1 && !uvcb.guest_handle,
	       "reuse ASCE");
	cgc_destroy_if_needed(&uvcb);
	free((void *)uvcb.conf_base_stor_origin);
	free((void *)uvcb.conf_var_stor_origin);

	/* Missing: 106, 10a, a0b */
	report_prefix_pop();
}

static void test_init(void)
{
	int rc;
	uint64_t tmp;

	/*
	 * Donated storage needs to be over 2GB, AREA_NORMAL does that
	 * on s390x.
	 */
	tmp = (uint64_t)memalign_pages_flags(SZ_1M, uvcb_qui.uv_base_stor_len, AREA_NORMAL);

	uvcb_init.header.len = sizeof(uvcb_init);
	uvcb_init.header.cmd = UVC_CMD_INIT_UV;
	uvcb_init.stor_origin = tmp;
	uvcb_init.stor_len = uvcb_qui.uv_base_stor_len;

	report_prefix_push("init");
	uvcb_init.header.len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb_init);
	report(rc == 1 && uvcb_init.header.rc == UVC_RC_INV_LEN,
	       "hdr invalid length");
	uvcb_init.header.len += 8;

	uvcb_init.stor_len -= 8;
	rc = uv_call(0, (uint64_t)&uvcb_init);
	report(rc == 1 && uvcb_init.header.rc == 0x103,
	       "storage invalid length");
	uvcb_init.stor_len += 8;

	/* Storage origin is 1MB aligned, the length is 4KB aligned */
	uvcb_init.stor_origin = get_max_ram_size();
	rc = uv_call(0, (uint64_t)&uvcb_init);
	report(rc == 1 && (uvcb_init.header.rc == 0x104 || uvcb_init.header.rc == 0x105),
	       "storage origin invalid");
	uvcb_init.stor_origin = tmp;

	if (uvcb_init.stor_len >= HPAGE_SIZE) {
		uvcb_init.stor_origin = get_max_ram_size() - HPAGE_SIZE;
		rc = uv_call(0, (uint64_t)&uvcb_init);
		report(rc == 1 && uvcb_init.header.rc == 0x105,
		       "storage + length invalid");
		uvcb_init.stor_origin = tmp;
	} else {
		report_skip("storage + length invalid, stor_len < HPAGE_SIZE");
	}

	uvcb_init.stor_origin = 1UL << 30;
	rc = uv_call(0, (uint64_t)&uvcb_init);
	report(rc == 1 && uvcb_init.header.rc == 0x108,
	       "storage below 2GB");
	uvcb_init.stor_origin = tmp;

	if (smp_query_num_cpus() > 1) {
		smp_cpu_setup(1, PSW_WITH_CUR_MASK(cpu_loop));
		rc = uv_call(0, (uint64_t)&uvcb_init);
		report(rc == 1 && uvcb_init.header.rc == 0x102,
		       "too many running cpus");
		smp_cpu_stop(1);
	} else {
		report_skip("Not enough cpus for 0x102 test");
	}

	rc = uv_call(0, (uint64_t)&uvcb_init);
	report(rc == 0 && uvcb_init.header.rc == UVC_RC_EXECUTED, "successful");

	tmp = uvcb_init.stor_origin;
	uvcb_init.stor_origin =	(uint64_t)memalign_pages_flags(HPAGE_SIZE, uvcb_qui.uv_base_stor_len, AREA_NORMAL);
	rc = uv_call(0, (uint64_t)&uvcb_init);
	report(rc == 1 && uvcb_init.header.rc == 0x101, "double init");
	free((void *)uvcb_init.stor_origin);
	uvcb_init.stor_origin = tmp;

	report_prefix_pop();
}

static void test_query(void)
{
	int i = 0, cc;

	uvcb_qui.header.cmd = UVC_CMD_QUI;
	uvcb_qui.header.len = sizeof(uvcb_qui);

	report_prefix_push("query");
	uvcb_qui.header.len = 0xa0;
	uv_call(0, (uint64_t)&uvcb_qui);
	report(uvcb_qui.header.rc == UVC_RC_INV_LEN, "length");

	uvcb_qui.header.len = 0xa8;
	uv_call(0, (uint64_t)&uvcb_qui);
	report(uvcb_qui.header.rc == 0x100, "insf length");

	uvcb_qui.header.len = sizeof(uvcb_qui);
	cc = uv_call(0, (uint64_t)&uvcb_qui);
	report((!cc && uvcb_qui.header.rc == UVC_RC_EXECUTED) ||
	       (cc == 1 && uvcb_qui.header.rc == 0x100),
		"successful query");

	for (i = 0; cmds[i].name; i++)
		report(uv_query_test_call(cmds[i].call_bit), "%s", cmds[i].name);

	report_prefix_pop();
}

static struct cmd_list invalid_cmds[] = {
	{ "bogus", 0x4242, sizeof(struct uv_cb_header), -1},
	{ "share", UVC_CMD_SET_SHARED_ACCESS, sizeof(struct uv_cb_share), BIT_UVC_CMD_SET_SHARED_ACCESS },
	{ "unshare", UVC_CMD_REMOVE_SHARED_ACCESS, sizeof(struct uv_cb_share), BIT_UVC_CMD_REMOVE_SHARED_ACCESS },
	{ "attest", UVC_CMD_ATTESTATION, sizeof(struct uv_cb_attest), BIT_UVC_CMD_ATTESTATION },
	{ NULL, 0, 0 },
};

static void test_invalid(void)
{
	struct uv_cb_header hdr = {};
	int i, cc;

	report_prefix_push("invalid");
	for (i = 0; invalid_cmds[i].name; i++) {
		hdr.cmd = invalid_cmds[i].cmd;
		hdr.len = invalid_cmds[i].len;
		cc = uv_call(0, (uint64_t)&hdr);
		report(cc == 1 && hdr.rc == UVC_RC_INV_CMD &&
		       (invalid_cmds[i].call_bit == -1 || !uv_query_test_call(invalid_cmds[i].call_bit)),
		       "%s", invalid_cmds[i].name);
	}
	report_prefix_pop();
}

static void setup_test_clear(void)
{
	unsigned long vsize;
	int rc;

	uvcb_cgc.header.cmd = UVC_CMD_CREATE_SEC_CONF;
	uvcb_cgc.header.len = sizeof(uvcb_cgc);

	uvcb_cgc.guest_stor_origin = 0;
	uvcb_cgc.guest_stor_len = 42 * (1UL << 20);
	vsize = uvcb_qui.conf_base_virt_stor_len +
		((uvcb_cgc.guest_stor_len / (1UL << 20)) * uvcb_qui.conf_virt_var_stor_len);

	uvcb_cgc.conf_base_stor_origin = (uint64_t)memalign(PAGE_SIZE * 4, uvcb_qui.conf_base_phys_stor_len);
	uvcb_cgc.conf_var_stor_origin = (uint64_t)memalign(PAGE_SIZE, vsize);
	uvcb_cgc.guest_asce = (uint64_t)memalign(PAGE_SIZE, 4 * PAGE_SIZE) | ASCE_DT_SEGMENT | REGION_TABLE_LENGTH | ASCE_P;
	uvcb_cgc.guest_sca = (uint64_t)memalign(PAGE_SIZE * 4, PAGE_SIZE * 4);

	rc = uv_call(0, (uint64_t)&uvcb_cgc);
	assert(rc == 0);

	uvcb_csc.header.len = sizeof(uvcb_csc);
	uvcb_csc.header.cmd = UVC_CMD_CREATE_SEC_CPU;
	uvcb_csc.guest_handle = uvcb_cgc.guest_handle;
	uvcb_csc.stor_origin = (unsigned long)memalign(PAGE_SIZE, uvcb_qui.cpu_stor_len);
	uvcb_csc.state_origin = (unsigned long)memalign(PAGE_SIZE, PAGE_SIZE);

	rc = uv_call(0, (uint64_t)&uvcb_csc);
	assert(rc == 0);
}

static void test_clear(void)
{
	uint64_t *tmp;

	report_prefix_push("load normal reset");

	/*
	 * Setup a config and a cpu so we can check if a diag308 reset
	 * clears the donated memory and makes the pages unsecure.
	 */
	setup_test_clear();

	diag308_load_reset(1);
	sclp_console_setup();

	tmp = (void *)uvcb_init.stor_origin;
	report(!*tmp, "uv init donated memory cleared");

	tmp = (void *)uvcb_cgc.conf_base_stor_origin;
	report(!*tmp, "config base donated memory cleared");

	tmp = (void *)uvcb_cgc.conf_base_stor_origin;
	report(!*tmp, "config variable donated memory cleared");

	tmp = (void *)uvcb_csc.stor_origin;
	report(!*tmp, "cpu donated memory cleared after reset 1");

	/* Check if uninitialized after reset */
	test_uv_uninitialized();

	report_prefix_pop();
}

static void setup_vmem(void)
{
	uint64_t asce;

	setup_mmu(get_max_ram_size(), NULL);
	/*
	 * setup_mmu() will enable DAT and set the primary address
	 * space but we need to have a valid home space since UV calls
	 * take home space virtual addresses.
	 *
	 * Hence we just copy the primary asce into the home space.
	 */
	asce = stctg(1);
	lctlg(13, asce);
}

int main(void)
{
	bool has_uvc = test_facility(158);

	report_prefix_push("uvc");
	if (!has_uvc) {
		report_skip("Ultravisor call facility is not available");
		goto done;
	}
	if (!uv_os_is_host()) {
		report_skip("This test needs to be run in a UV host environment");
		goto done;
	}

	test_i3();
	test_priv();
	test_invalid();
	test_uv_uninitialized();
	test_query();

	if (get_ram_size() < SNIPPET_PV_MIN_MEM_SIZE) {
		report_skip("Not enough memory. This test needs about %ld MB of memory",
			    SNIPPET_PV_MIN_MEM_SIZE / SZ_1M);
		goto done;
	}

	test_init();

	setup_vmem();
	test_access();

	test_config_create();
	test_cpu_create();
	test_set_se_header();
	test_cpu_destroy();
	test_config_destroy();
	test_clear();

done:
	return report_summary();
}
