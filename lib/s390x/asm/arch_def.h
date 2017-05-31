/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#ifndef _ASM_S390X_ARCH_DEF_H_
#define _ASM_S390X_ARCH_DEF_H_

struct psw {
	uint64_t	mask;
	uint64_t	addr;
};

struct lowcore {
	uint8_t		pad_0x0000[0x0080 - 0x0000];	/* 0x0000 */
	uint32_t	ext_int_param;			/* 0x0080 */
	uint16_t	cpu_addr;			/* 0x0084 */
	uint16_t	ext_int_code;			/* 0x0086 */
	uint16_t	svc_int_id;			/* 0x0088 */
	uint16_t	svc_int_code;			/* 0x008a */
	uint16_t	pgm_int_id;			/* 0x008c */
	uint16_t	pgm_int_code;			/* 0x008e */
	uint32_t	dxc_vxc;			/* 0x0090 */
	uint16_t	mon_class_nb;			/* 0x0094 */
	uint8_t		per_code;			/* 0x0096 */
	uint8_t		per_atmid;			/* 0x0097 */
	uint64_t	per_addr;			/* 0x0098 */
	uint8_t		exc_acc_id;			/* 0x00a0 */
	uint8_t		per_acc_id;			/* 0x00a1 */
	uint8_t		op_acc_id;			/* 0x00a2 */
	uint8_t		arch_mode_id;			/* 0x00a3 */
	uint8_t		pad_0x00a4[0x00a8 - 0x00a4];	/* 0x00a4 */
	uint64_t	trans_exc_id;			/* 0x00a8 */
	uint64_t	mon_code;			/* 0x00b0 */
	uint32_t	subsys_id_word;			/* 0x00b8 */
	uint32_t	io_int_param;			/* 0x00bc */
	uint32_t	io_int_word;			/* 0x00c0 */
	uint8_t		pad_0x00c4[0x00c8 - 0x00c4];	/* 0x00c4 */
	uint32_t	stfl;				/* 0x00c8 */
	uint8_t		pad_0x00cc[0x00e8 - 0x00cc];	/* 0x00cc */
	uint64_t	mcck_int_code;			/* 0x00e8 */
	uint8_t		pad_0x00f0[0x00f4 - 0x00f0];	/* 0x00f0 */
	uint32_t	ext_damage_code;		/* 0x00f4 */
	uint64_t	failing_storage_addr;		/* 0x00f8 */
	uint64_t	emon_ca_origin;			/* 0x0100 */
	uint32_t	emon_ca_size;			/* 0x0108 */
	uint32_t	emon_exc_count;			/* 0x010c */
	uint64_t	breaking_event_addr;		/* 0x0110 */
	uint8_t		pad_0x0118[0x0120 - 0x0118];	/* 0x0118 */
	struct psw	restart_old_psw;		/* 0x0120 */
	struct psw	ext_old_psw;			/* 0x0130 */
	struct psw	svc_old_psw;			/* 0x0140 */
	struct psw	pgm_old_psw;			/* 0x0150 */
	struct psw	mcck_old_psw;			/* 0x0160 */
	struct psw	io_old_psw;			/* 0x0170 */
	uint8_t		pad_0x0180[0x01a0 - 0x0180];	/* 0x0180 */
	struct psw	restart_new_psw;		/* 0x01a0 */
	struct psw	ext_new_psw;			/* 0x01b0 */
	struct psw	svc_new_psw;			/* 0x01c0 */
	struct psw	pgm_new_psw;			/* 0x01d0 */
	struct psw	mcck_new_psw;			/* 0x01e0 */
	struct psw	io_new_psw;			/* 0x01f0 */
	uint8_t		pad_0x0200[0x11b0 - 0x0200];	/* 0x0200 */
	uint64_t	mcck_ext_sa_addr;		/* 0x11b0 */
	uint8_t		pad_0x11b8[0x1200 - 0x11b8];	/* 0x11b8 */
	uint64_t	fprs_sa[16];			/* 0x1200 */
	uint64_t	grs_sa[16];			/* 0x1280 */
	struct psw	psw_sa;				/* 0x1300 */
	uint8_t		pad_0x1310[0x1318 - 0x1310];	/* 0x1310 */
	uint32_t	prefix_sa;			/* 0x1318 */
	uint32_t	fpc_sa;				/* 0x131c */
	uint8_t		pad_0x1320[0x1324 - 0x1320];	/* 0x1320 */
	uint32_t	tod_pr_sa;			/* 0x1324 */
	uint64_t	cputm_sa;			/* 0x1328 */
	uint64_t	cc_sa;				/* 0x1330 */
	uint8_t		pad_0x1338[0x1340 - 0x1338];	/* 0x1338 */
	uint32_t	ars_sa[16];			/* 0x1340 */
	uint64_t	crs_sa[16];			/* 0x1380 */
	uint8_t		pad_0x1400[0x1800 - 0x1400];	/* 0x1400 */
	uint8_t		pgm_int_tdb[0x1900 - 0x1800];	/* 0x1800 */
} __attribute__ ((__packed__));

#endif
