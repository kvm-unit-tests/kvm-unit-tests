/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * STHYI related flags and structure definitions.
 *
 * Copyright 2018 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.vnet.ibm.com>
 */
#ifndef S390X_STHYI_H
#define S390X_STHYI_H

#include <stdint.h>

enum sthyi_rtn_code {
	CODE_UNSUPP = 0x04, /* with cc = 3 */
	CODE_SUCCES = 0x00, /* with cc = 0 */
};

enum sthyi_hdr_flags {
	HDR_PERF_UNAV  = 0x80,
	HDR_STSI_UNAV  = 0x40,
	HDR_STACK_INCM = 0x20,
	HDR_NOT_LPAR   = 0x10,
};

enum sthyi_mach_validity {
	MACH_CNT_VLD  = 0x80,
	MACH_ID_VLD   = 0x40,
	MACH_NAME_VLD = 0x20,
};

enum sthyi_par_flag {
	PART_MT_EN = 0x80,
};

enum sthyi_par_validity {
	PART_CNT_VLD  = 0x80,
	PART_WGHT_CAP = 0x40,
	PART_ABS_CAP  = 0x20,
	PART_STSI_SUC = 0x10,
	PART_GRP_VLD  = 0x08,
};

struct sthyi_hdr_sctn {
	uint8_t INFHFLG1;
	uint8_t INFHFLG2; /* reserved */
	uint8_t INFHVAL1; /* reserved */
	uint8_t INFHVAL2; /* reserved */
	uint8_t reserved[3];
	uint8_t INFHYGCT;
	uint16_t INFHTOTL;
	uint16_t INFHDLN;
	uint16_t INFMOFF;
	uint16_t INFMLEN;
	uint16_t INFPOFF;
	uint16_t INFPLEN;
	uint16_t INFHOFF1;
	uint16_t INFHLEN1;
	uint16_t INFGOFF1;
	uint16_t INFGLEN1;
	uint16_t INFHOFF2;
	uint16_t INFHLEN2;
	uint16_t INFGOFF2;
	uint16_t INFGLEN2;
	uint16_t INFHOFF3;
	uint16_t INFHLEN3;
	uint16_t INFGOFF3;
	uint16_t INFGLEN3;
	uint8_t reserved2[4];
} __attribute__((packed));

struct sthyi_mach_sctn {
	uint8_t INFMFLG1; /* reserved */
	uint8_t INFMFLG2; /* reserved */
	uint8_t INFMVAL1;
	uint8_t INFMVAL2; /* reserved */
	uint16_t INFMSCPS;
	uint16_t INFMDCPS;
	uint16_t INFMSIFL;
	uint16_t INFMDIFL;
	char INFMNAME[8];
	char INFMTYPE[4];
	char INFMMANU[16];
	char INFMSEQ[16];
	char INFMPMAN[4];
	uint8_t reserved[4];
} __attribute__((packed));

struct sthyi_par_sctn {
	uint8_t INFPFLG1;
	uint8_t INFPFLG2; /* reserved */
	uint8_t INFPVAL1;
	uint8_t INFPVAL2; /* reserved */
	uint16_t INFPPNUM;
	uint16_t INFPSCPS;
	uint16_t INFPDCPS;
	uint16_t INFPSIFL;
	uint16_t INFPDIFL;
	uint16_t reserved;
	char INFPPNAM[8];
	uint32_t INFPWBCP;
	uint32_t INFPABCP;
	uint32_t INFPWBIF;
	uint32_t INFPABIF;
} __attribute__((packed));

struct sthyi_par_sctn_ext {
	uint8_t INFPFLG1;
	uint8_t INFPFLG2; /* reserved */
	uint8_t INFPVAL1;
	uint8_t INFPVAL2; /* reserved */
	uint16_t INFPPNUM;
	uint16_t INFPSCPS;
	uint16_t INFPDCPS;
	uint16_t INFPSIFL;
	uint16_t INFPDIFL;
	uint16_t reserved;
	char INFPPNAM[8];
	uint32_t INFPWBCP;
	uint32_t INFPABCP;
	uint32_t INFPWBIF;
	uint32_t INFPABIF;
	char INFPLGNM[8];
	uint32_t INFPLGCP;
	uint32_t INFPLGIF;
} __attribute__((packed));

#endif
