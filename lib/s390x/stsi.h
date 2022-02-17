/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Structures used to Store System Information
 *
 * Copyright IBM Corp. 2022
 */

#ifndef _S390X_STSI_H_
#define _S390X_STSI_H_

struct sysinfo_3_2_2 {
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

#endif  /* _S390X_STSI_H_ */
