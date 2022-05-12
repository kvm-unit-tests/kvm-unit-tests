/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Retrieve Attestation Measurement Utravisor Call tests
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Steffen Eiden <seiden@linux.ibm.com>
 */

#include <libcflat.h>
#include <alloc_page.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/uv.h>
#include <sclp.h>
#include <uv.h>

#define ARCB_VERSION_NONE 0
#define ARCB_VERSION_1 0x100
#define ARCB_MEAS_NONE 0
#define ARCB_MEAS_HMAC_SHA512 1
#define MEASUREMENT_SIZE_HMAC_SHA512 64
#define PAF_PHKH_ATT (1ULL << 61)
#define ADDITIONAL_SIZE_PAF_PHKH_ATT 32
/* arcb with one key slot and no nonce */
struct uv_arcb_v1 {
	uint64_t reserved0;		/* 0x0000 */
	uint32_t req_ver;		/* 0x0008 */
	uint32_t req_len;		/* 0x000c */
	uint8_t  iv[12];		/* 0x0010 */
	uint32_t reserved1c;		/* 0x001c */
	uint8_t  reserved20[7];		/* 0x0020 */
	uint8_t  nks;			/* 0x0027 */
	int32_t reserved28;		/* 0x0028 */
	uint32_t sea;			/* 0x002c */
	uint64_t plaint_att_flags;	/* 0x0030 */
	uint32_t meas_alg_id;		/* 0x0038 */
	uint32_t reserved3c;		/* 0x003c */
	uint8_t  cpk[160];		/* 0x0040 */
	uint8_t  key_slot[80];		/* 0x00e0 */
	uint8_t  meas_key[64];		/* 0x0130 */
	uint8_t  tag[16];		/* 0x0170 */
} __attribute__((packed));

struct attest_request_v1 {
	struct uv_arcb_v1 arcb;
	uint8_t measurement[MEASUREMENT_SIZE_HMAC_SHA512];
	uint8_t additional[ADDITIONAL_SIZE_PAF_PHKH_ATT];
};

static void test_attest_v1(uint64_t page)
{
	struct uv_cb_attest uvcb = {
		.header.cmd = UVC_CMD_ATTESTATION,
		.header.len = sizeof(uvcb),
	};
	const struct uv_cb_qui *uvcb_qui = uv_get_query_data();
	struct attest_request_v1 *attest_req = (void *)page;
	struct uv_arcb_v1 *arcb = &attest_req->arcb;
	int cc;

	report_prefix_push("v1");
	if (!test_bit_inv(0, &uvcb_qui->supp_att_hdr_ver)) {
		report_skip("Attestation version 1 not supported");
		goto done;
	}

	memset((void *)page, 0, PAGE_SIZE);

	/*
	 * Create a minimal arcb/uvcb such that FW has everything to start
	 * unsealing the request. However, this unsealing will fail as the
	 * kvm-unit-test framework provides no cryptography functions that
	 * would be needed to seal such requests.
	 */
	arcb->req_ver = ARCB_VERSION_1;
	arcb->req_len = sizeof(*arcb);
	arcb->nks = 1;
	arcb->sea = sizeof(arcb->meas_key);
	arcb->plaint_att_flags = PAF_PHKH_ATT;
	arcb->meas_alg_id = ARCB_MEAS_HMAC_SHA512;
	uvcb.arcb_addr = (uint64_t)&attest_req->arcb;
	uvcb.measurement_address = (uint64_t)attest_req->measurement;
	uvcb.measurement_length = sizeof(attest_req->measurement);
	uvcb.add_data_address = (uint64_t)attest_req->additional;
	uvcb.add_data_length = sizeof(attest_req->additional);

	uvcb.continuation_token = 0xff;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x101, "invalid continuation token");
	uvcb.continuation_token = 0;

	uvcb.user_data_length = sizeof(uvcb.user_data) + 1;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x102, "invalid user data size");
	uvcb.user_data_length = 0;

	uvcb.arcb_addr = get_ram_size() + PAGE_SIZE;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x103, "invalid address arcb");
	uvcb.arcb_addr = page;

	/* 0x104 - 0x105 need an unseal-able request */

	arcb->req_ver = ARCB_VERSION_NONE;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x106, "unsupported version");
	arcb->req_ver = ARCB_VERSION_1;

	arcb->req_len += 1;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x107, "arcb too big");
	arcb->req_len -= 1;

	/*
	 * The arcb needs to grow as well if number of key slots (nks)
	 * is increased. However, this is not the case and there is no explicit
	 * 'too many/less nks for that arcb size' error code -> expect 0x107
	 */
	arcb->nks = 2;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x107, "too many nks for arcb");
	arcb->nks = 1;

	arcb->nks = 0;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x108, "invalid num key slots");
	arcb->nks = 1;

	/*
	 * Possible valid size (when using nonce).
	 * However, req_len too small to host a nonce
	 */
	arcb->sea = 80;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x109, "encrypted size too big");
	arcb->sea = 17;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x109, "encrypted size too small");
	arcb->sea = 64;

	arcb->plaint_att_flags = uvcb_qui->supp_paf ^ GENMASK_ULL(63, 0);
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x10a, "invalid flag");
	arcb->plaint_att_flags = PAF_PHKH_ATT;

	arcb->meas_alg_id = ARCB_MEAS_NONE;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x10b, "invalid measurement algorithm");
	arcb->meas_alg_id = ARCB_MEAS_HMAC_SHA512;

	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x10c, "unable unseal");

	uvcb.measurement_length = 0;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x10d, "invalid measurement size");
	uvcb.measurement_length = sizeof(attest_req->measurement);

	uvcb.add_data_length = 0;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc == 1 && uvcb.header.rc == 0x10e, "invalid additional size");
	uvcb.add_data_length = sizeof(attest_req->additional);

done:
	report_prefix_pop();
}

static void test_attest(uint64_t page)
{
	struct uv_cb_attest uvcb = {
		.header.cmd = UVC_CMD_ATTESTATION,
		.header.len = sizeof(uvcb),
	};
	const struct uv_cb_qui *uvcb_qui = uv_get_query_data();
	int cc;

	/* Verify that the UV supports at least one header version */
	report(uvcb_qui->supp_att_hdr_ver, "has hdr support");

	memset((void *)page, 0, PAGE_SIZE);

	uvcb.header.len -= 1;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc && uvcb.header.rc == UVC_RC_INV_LEN, "uvcb too small");
	uvcb.header.len += 1;

	uvcb.header.len += 1;
	cc = uv_call(0, (uint64_t)&uvcb);
	report(cc && uvcb.header.rc == UVC_RC_INV_LEN, "uvcb too large");
	uvcb.header.len -= 1;
}

int main(void)
{
	bool has_uvc = test_facility(158);
	uint64_t page;


	report_prefix_push("attestation");
	if (!has_uvc) {
		report_skip("Ultravisor call facility is not available");
		goto done;
	}

	if (!uv_os_is_guest()) {
		report_skip("Not a protected guest");
		goto done;
	}

	if (!uv_query_test_call(BIT_UVC_CMD_ATTESTATION)) {
		report_skip("Attestation not supported.");
		goto done;
	}

	page = (uint64_t)alloc_page();
	/* The privilege check is done in uv-guest.c */
	test_attest(page);
	test_attest_v1(page);
	free_page((void *)page);
done:
	report_prefix_pop();
	return report_summary();
}
