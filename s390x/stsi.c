/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Store System Information tests
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */

#include <libcflat.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <smp.h>

struct stsi_322 {
	uint8_t reserved[31];
	uint8_t count;
	struct {
		uint8_t reserved2[4];
		uint16_t total_cpus;
		uint16_t conf_cpus;
		uint16_t standby_cpus;
		uint16_t reserved_cpus;
		uint8_t name[8];
		uint32_t caf;
		uint8_t cpi[16];
		uint8_t reserved5[3];
		uint8_t ext_name_encoding;
		uint32_t reserved3;
		uint8_t uuid[16];
	} vm[8];
	uint8_t reserved4[1504];
	uint8_t ext_names[8][256];
};
static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));

static void test_specs(void)
{
	report_prefix_push("specification");

	report_prefix_push("inv r0");
	expect_pgm_int();
	stsi(pagebuf, 0, 1 << 8, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("inv r1");
	expect_pgm_int();
	stsi(pagebuf, 1, 0, 1 << 16);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_push("unaligned");
	expect_pgm_int();
	stsi(pagebuf + 42, 1, 1, 1);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();

	report_prefix_pop();
}

static void test_priv(void)
{
	report_prefix_push("privileged");
	expect_pgm_int();
	enter_pstate();
	stsi(pagebuf, 0, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_PRIVILEGED_OPERATION);
	report_prefix_pop();
}

static void test_fc(void)
{
	report(stsi(pagebuf, 7, 0, 0) == 3, "invalid fc");
	report(stsi(pagebuf, 1, 0, 1) == 3, "invalid selector 1");
	report(stsi(pagebuf, 1, 1, 0) == 3, "invalid selector 2");
	report(stsi_get_fc() >= 2, "query fc >= 2");
}

static void test_3_2_2(void)
{
	int rc;
	/* EBCDIC for "kvm-unit" */
	const uint8_t vm_name[] = { 0x92, 0xa5, 0x94, 0x60, 0xa4, 0x95, 0x89,
				    0xa3 };
	const uint8_t uuid[] = { 0x0f, 0xb8, 0x4a, 0x86, 0x72, 0x7c,
				 0x11, 0xea, 0xbc, 0x55, 0x02, 0x42, 0xac, 0x13,
				 0x00, 0x03 };
	/* EBCDIC for "KVM/" */
	const uint8_t cpi_kvm[] = { 0xd2, 0xe5, 0xd4, 0x61 };
	const char vm_name_ext[] = "kvm-unit-test";
	struct stsi_322 *data = (void *)pagebuf;

	report_prefix_push("3.2.2");

	/* Is the function code available at all? */
	if (stsi_get_fc() < 3) {
		report_skip("Running under lpar, no level 3 to test.");
		goto out;
	}

	rc = stsi(pagebuf, 3, 2, 2);
	report(!rc, "call");

	/* For now we concentrate on KVM/QEMU */
	if (memcmp(&data->vm[0].cpi, cpi_kvm, sizeof(cpi_kvm))) {
		report_skip("Not running under KVM/QEMU.");
		goto out;
	}

	report(!memcmp(data->vm[0].uuid, uuid, sizeof(uuid)), "uuid");
	report(data->vm[0].conf_cpus == smp_query_num_cpus(), "cpu count configured");
	report(data->vm[0].total_cpus ==
	       data->vm[0].reserved_cpus + data->vm[0].conf_cpus,
	       "cpu count total == conf + reserved");
	report(data->vm[0].standby_cpus == 0, "cpu count standby");
	report(!memcmp(data->vm[0].name, vm_name, sizeof(data->vm[0].name)),
	       "VM name == kvm-unit-test");

	if (data->vm[0].ext_name_encoding != 2) {
		report_skip("Extended VM names are not UTF-8.");
		goto out;
	}
	report(!memcmp(data->ext_names[0], vm_name_ext, sizeof(vm_name_ext)),
		       "ext VM name == kvm-unit-test");

out:
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("stsi");
	test_priv();
	test_specs();
	test_fc();
	test_3_2_2();
	return report_summary();
}
