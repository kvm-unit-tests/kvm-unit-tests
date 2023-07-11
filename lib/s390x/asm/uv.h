/*
 * s390x Ultravisor related definitions
 *
 * Copyright IBM Corp. 2020, 2022
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */
#ifndef _ASMS390X_UV_H_
#define _ASMS390X_UV_H_

/* Enables printing of command code and return codes for failed UVCs */
#ifndef UVC_ERR_DEBUG
#define UVC_ERR_DEBUG	0
#endif

#define UVC_RC_EXECUTED		0x0001
#define UVC_RC_INV_CMD		0x0002
#define UVC_RC_INV_STATE	0x0003
#define UVC_RC_INV_LEN		0x0005
#define UVC_RC_NO_RESUME	0x0007
#define UVC_RC_INV_GHANDLE	0x0020
#define UVC_RC_INV_CHANDLE	0x0021
#define UVC_RC_DSTR_NEEDED_FLG	0x8000

#define UVC_CMD_QUI			0x0001
#define UVC_CMD_INIT_UV			0x000f
#define UVC_CMD_CREATE_SEC_CONF		0x0100
#define UVC_CMD_DESTROY_SEC_CONF	0x0101
#define UVC_CMD_CREATE_SEC_CPU		0x0120
#define UVC_CMD_DESTROY_SEC_CPU		0x0121
#define UVC_CMD_CONV_TO_SEC_STOR	0x0200
#define UVC_CMD_CONV_FROM_SEC_STOR	0x0201
#define UVC_CMD_DESTR_SEC_STOR		0x0202
#define UVC_CMD_SET_SEC_CONF_PARAMS	0x0300
#define UVC_CMD_UNPACK_IMG		0x0301
#define UVC_CMD_VERIFY_IMG		0x0302
#define UVC_CMD_CPU_RESET		0x0310
#define UVC_CMD_CPU_RESET_INITIAL	0x0311
#define UVC_CMD_PREPARE_RESET		0x0320
#define UVC_CMD_CPU_RESET_CLEAR		0x0321
#define UVC_CMD_CPU_SET_STATE		0x0330
#define UVC_CMD_SET_UNSHARED_ALL	0x0340
#define UVC_CMD_PIN_PAGE_SHARED		0x0341
#define UVC_CMD_UNPIN_PAGE_SHARED	0x0342
#define UVC_CMD_SET_SHARED_ACCESS	0x1000
#define UVC_CMD_REMOVE_SHARED_ACCESS	0x1001
#define UVC_CMD_ATTESTATION		0x1020

/* Bits in installed uv calls */
enum uv_cmds_inst {
	BIT_UVC_CMD_QUI = 0,
	BIT_UVC_CMD_INIT_UV = 1,
	BIT_UVC_CMD_CREATE_SEC_CONF = 2,
	BIT_UVC_CMD_DESTROY_SEC_CONF = 3,
	BIT_UVC_CMD_CREATE_SEC_CPU = 4,
	BIT_UVC_CMD_DESTROY_SEC_CPU = 5,
	BIT_UVC_CMD_CONV_TO_SEC_STOR = 6,
	BIT_UVC_CMD_CONV_FROM_SEC_STOR = 7,
	BIT_UVC_CMD_SET_SHARED_ACCESS = 8,
	BIT_UVC_CMD_REMOVE_SHARED_ACCESS = 9,
	BIT_UVC_CMD_SET_SEC_PARMS = 11,
	BIT_UVC_CMD_UNPACK_IMG = 13,
	BIT_UVC_CMD_VERIFY_IMG = 14,
	BIT_UVC_CMD_CPU_RESET = 15,
	BIT_UVC_CMD_CPU_RESET_INITIAL = 16,
	BIT_UVC_CMD_CPU_SET_STATE = 17,
	BIT_UVC_CMD_PREPARE_RESET = 18,
	BIT_UVC_CMD_CPU_PERFORM_CLEAR_RESET = 19,
	BIT_UVC_CMD_UNSHARE_ALL = 20,
	BIT_UVC_CMD_PIN_PAGE_SHARED = 21,
	BIT_UVC_CMD_UNPIN_PAGE_SHARED = 22,
	BIT_UVC_CMD_ATTESTATION = 28,
};

struct uv_cb_header {
	u16 len;
	u16 cmd;	/* Command Code */
	u16 rc;		/* Response Code */
	u16 rrc;	/* Return Reason Code */
} __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_init {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 stor_origin;
	u64 stor_len;
	u64 reserved28[4];

} __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_qui {
	struct uv_cb_header header;	/* 0x0000 */
	u64 reserved08;			/* 0x0008 */
	u64 inst_calls_list[4];		/* 0x0010 */
	u64 reserved30[2];		/* 0x0030 */
	u64 uv_base_stor_len;		/* 0x0040 */
	u64 reserved48;			/* 0x0048 */
	u64 conf_base_phys_stor_len;	/* 0x0050 */
	u64 conf_base_virt_stor_len;	/* 0x0058 */
	u64 conf_virt_var_stor_len;	/* 0x0060 */
	u64 cpu_stor_len;		/* 0x0068 */
	u32 reserved70[3];		/* 0x0070 */
	u32 max_num_sec_conf;		/* 0x007c */
	u64 max_guest_stor_addr;	/* 0x0080 */
	u8  reserved88[158 - 136];	/* 0x0088 */
	uint16_t max_guest_cpus;	/* 0x009e */
	u64 uv_feature_indications;	/* 0x00a0 */
	uint8_t  reserveda8[224 - 168];	/* 0x00a8 */
	uint64_t supp_att_hdr_ver;	/* 0x00e0 */
	uint64_t supp_paf;		/* 0x00e8 */
	uint8_t  reservedf0[256 - 240];	/* 0x00f0 */
}  __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_cgc {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 guest_handle;
	u64 conf_base_stor_origin;
	u64 conf_var_stor_origin;
	u64 reserved30;
	u64 guest_stor_origin;
	u64 guest_stor_len;
	u64 guest_sca;
	u64 guest_asce;
	u64 reserved60[5];
} __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_csc {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 cpu_handle;
	u64 guest_handle;
	u64 stor_origin;
	u8  reserved30[6];
	u16 num;
	u64 state_origin;
	u64 reserved[4];
} __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_unp {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 guest_handle;
	u64 gaddr;
	u64 tweak[2];
	u64 reserved38[3];
} __attribute__((packed))  __attribute__((aligned(8)));

/*
 * A common UV call struct for the following calls:
 * Destroy cpu/config
 * Verify
 */
struct uv_cb_nodata {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 handle;
	u64 reserved20[4];
}  __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_share {
	struct uv_cb_header header;
	u64 reserved08[3];
	u64 paddr;
	u64 reserved28;
} __attribute__((packed))  __attribute__((aligned(8)));

/* Convert to Secure */
struct uv_cb_cts {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 guest_handle;
	u64 gaddr;
}  __attribute__((packed))  __attribute__((aligned(8)));

/* Convert from Secure / Pin Page Shared */
struct uv_cb_cfs {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 paddr;
}  __attribute__((packed))  __attribute__((aligned(8)));

/* Retrieve Attestation Measurement */
struct uv_cb_attest {
	struct uv_cb_header header;	/* 0x0000 */
	uint64_t reserved08[2];		/* 0x0008 */
	uint64_t arcb_addr;		/* 0x0018 */
	uint64_t continuation_token;	/* 0x0020 */
	uint8_t  reserved28[6];		/* 0x0028 */
	uint16_t user_data_length;	/* 0x002e */
	uint8_t  user_data[256];	/* 0x0030 */
	uint32_t reserved130[3];	/* 0x0130 */
	uint32_t measurement_length;	/* 0x013c */
	uint64_t measurement_address;	/* 0x0140 */
	uint8_t  config_uid[16];	/* 0x0148 */
	uint32_t reserved158;		/* 0x0158 */
	uint32_t add_data_length;	/* 0x015c */
	uint64_t add_data_address;	/* 0x0160 */
	uint64_t reserved168[4];	/* 0x0168 */
}  __attribute__((packed))  __attribute__((aligned(8)));

/* Set Secure Config Parameter */
struct uv_cb_ssc {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 guest_handle;
	u64 sec_header_origin;
	u32 sec_header_len;
	u32 reserved2c;
	u64 reserved30[4];
} __attribute__((packed))  __attribute__((aligned(8)));

static inline int uv_call_once(unsigned long r1, unsigned long r2)
{
	int cc;

	asm volatile(
		"0:	.insn rrf,0xB9A40000,%[r1],%[r2],0,0\n"
		"		ipm	%[cc]\n"
		"		srl	%[cc],28\n"
		: [cc] "=d" (cc)
		: [r1] "a" (r1), [r2] "a" (r2)
		: "memory", "cc");

	if (UVC_ERR_DEBUG && cc == 1)
		printf("UV call error: call %x rc %x rrc %x\n",
		       ((struct uv_cb_header *)r2)->cmd,
		       ((struct uv_cb_header *)r2)->rc,
		       ((struct uv_cb_header *)r2)->rrc);

	return cc;
}

static inline int uv_call(unsigned long r1, unsigned long r2)
{
	int cc;

	/*
	 * CC 2 and 3 tell us to re-execute because the instruction
	 * hasn't yet finished.
	 */
	do {
		cc = uv_call_once(r1, r2);
	} while (cc > 1);

	return cc;
}

static inline int share(unsigned long addr, u16 cmd)
{
	struct uv_cb_share uvcb = {
		.header.cmd = cmd,
		.header.len = sizeof(uvcb),
		.paddr = addr
	};

	return uv_call(0, (u64)&uvcb);
}

/*
 * Guest 2 request to the Ultravisor to make a page shared with the
 * hypervisor for IO.
 *
 * @addr: Real or absolute address of the page to be shared
 */
static inline int uv_set_shared(unsigned long addr)
{
	return share(addr, UVC_CMD_SET_SHARED_ACCESS);
}

/*
 * Guest 2 request to the Ultravisor to make a page unshared.
 *
 * @addr: Real or absolute address of the page to be unshared
 */
static inline int uv_remove_shared(unsigned long addr)
{
	return share(addr, UVC_CMD_REMOVE_SHARED_ACCESS);
}

static inline int uv_cmd_nodata(uint64_t handle, uint16_t cmd, uint16_t *rc, uint16_t *rrc)
{
	struct uv_cb_nodata uvcb = {
		.header.cmd = cmd,
		.header.len = sizeof(uvcb),
		.handle = handle,
	};
	int cc;

	assert(handle);
	cc = uv_call(0, (uint64_t)&uvcb);
	*rc = uvcb.header.rc;
	*rrc = uvcb.header.rrc;
	return cc;
}

static inline int uv_import(uint64_t handle, unsigned long gaddr)
{
	struct uv_cb_cts uvcb = {
		.header.cmd = UVC_CMD_CONV_TO_SEC_STOR,
		.header.len = sizeof(uvcb),
		.guest_handle = handle,
		.gaddr = gaddr,
	};

	return uv_call(0, (uint64_t)&uvcb);
}

static inline int uv_export(unsigned long paddr)
{
	struct uv_cb_cfs uvcb = {
		.header.cmd = UVC_CMD_CONV_FROM_SEC_STOR,
		.header.len = sizeof(uvcb),
		.paddr = paddr
	};

	return uv_call(0, (u64)&uvcb);
}

/*
 * Requests the Ultravisor to destroy a guest page and make it
 * accessible to the host. The destroy clears the page instead of
 * exporting.
 *
 * @paddr: Absolute host address of page to be destroyed
 */
static inline int uv_destroy_page(unsigned long paddr)
{
	struct uv_cb_cfs uvcb = {
		.header.cmd = UVC_CMD_DESTR_SEC_STOR,
		.header.len = sizeof(uvcb),
		.paddr = paddr
	};

	return uv_call(0, (uint64_t)&uvcb);
}

struct uv_cb_cpu_set_state {
	struct uv_cb_header header;
	u64 reserved08[2];
	u64 cpu_handle;
	u8  reserved20[7];
	u8  state;
	u64 reserved28[5];
};

#define PV_CPU_STATE_OPR	1
#define PV_CPU_STATE_STP	2
#define PV_CPU_STATE_CHKSTP	3
#define PV_CPU_STATE_OPR_LOAD	5

static inline int uv_set_cpu_state(uint64_t handle, uint8_t state)
{
	struct uv_cb_cpu_set_state uvcb = {
		.header.cmd = UVC_CMD_CPU_SET_STATE,
		.header.len = sizeof(uvcb),
		.cpu_handle = handle,
		.state = state,
	};

	assert(handle);
	return uv_call(0, (uint64_t)&uvcb);
}

static inline int uv_set_se_hdr(uint64_t handle, void *hdr, size_t len)
{
	struct uv_cb_ssc uvcb = {
		.header.cmd = UVC_CMD_SET_SEC_CONF_PARAMS,
		.header.len = sizeof(uvcb),
		.sec_header_origin = (uint64_t)hdr,
		.sec_header_len = len,
		.guest_handle = handle,
	};

	assert(handle);
	return uv_call(0, (uint64_t)&uvcb);
}

static inline int uv_unp_page(uint64_t handle, uint64_t gaddr, uint64_t tweak1, uint64_t tweak2)
{
	struct uv_cb_unp uvcb = {
		.header.cmd = UVC_CMD_UNPACK_IMG,
		.header.len = sizeof(uvcb),
		.guest_handle = handle,
		.gaddr = gaddr,
		.tweak[0] = tweak1,
		.tweak[1] = tweak2,
	};

	return uv_call(0, (uint64_t)&uvcb);
}

#endif
