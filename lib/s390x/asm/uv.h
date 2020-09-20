/*
 * s390x Ultravisor related definitions
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */
#ifndef UV_H
#define UV_H

#define UVC_RC_EXECUTED		0x0001
#define UVC_RC_INV_CMD		0x0002
#define UVC_RC_INV_STATE	0x0003
#define UVC_RC_INV_LEN		0x0005
#define UVC_RC_NO_RESUME	0x0007

#define UVC_CMD_QUI			0x0001
#define UVC_CMD_SET_SHARED_ACCESS	0x1000
#define UVC_CMD_REMOVE_SHARED_ACCESS	0x1001

/* Bits in installed uv calls */
enum uv_cmds_inst {
	BIT_UVC_CMD_QUI = 0,
	BIT_UVC_CMD_SET_SHARED_ACCESS = 8,
	BIT_UVC_CMD_REMOVE_SHARED_ACCESS = 9,
};

struct uv_cb_header {
	u16 len;
	u16 cmd;	/* Command Code */
	u16 rc;		/* Response Code */
	u16 rrc;	/* Return Reason Code */
} __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_qui {
	struct uv_cb_header header;
	u64 reserved08;
	u64 inst_calls_list[4];
	u64 reserved30[15];
} __attribute__((packed))  __attribute__((aligned(8)));

struct uv_cb_share {
	struct uv_cb_header header;
	u64 reserved08[3];
	u64 paddr;
	u64 reserved28;
} __attribute__((packed))  __attribute__((aligned(8)));

static inline int uv_call(unsigned long r1, unsigned long r2)
{
	int cc;

	/*
	 * The brc instruction will take care of the cc 2/3 case where
	 * we need to continue the execution because we were
	 * interrupted. The inline assembly will only return on
	 * success/error i.e. cc 0/1.
	*/
	asm volatile(
		"0:	.insn rrf,0xB9A40000,%[r1],%[r2],0,0\n"
		"		brc	3,0b\n"
		"		ipm	%[cc]\n"
		"		srl	%[cc],28\n"
		: [cc] "=d" (cc)
		: [r1] "a" (r1), [r2] "a" (r2)
		: "memory", "cc");
	return cc;
}

#endif
