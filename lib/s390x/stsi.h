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

#define CPUS_TLE_RES_BITS 0x00fffffff8000000UL
union topology_cpu {
	uint64_t raw[2];
	struct {
		uint8_t nl;
		uint8_t reserved1[3];
		uint8_t reserved4:5;
		uint8_t d:1;
		uint8_t pp:2;
		uint8_t type;
		uint16_t origin;
		uint64_t mask;
	};
};

enum topology_polarization {
	POLARIZATION_HORIZONTAL = 0,
	POLARIZATION_VERTICAL_LOW = 1,
	POLARIZATION_VERTICAL_MEDIUM = 2,
	POLARIZATION_VERTICAL_HIGH = 3,
};

enum cpu_type {
	CPU_TYPE_IFL = 3,
};

#define CONTAINER_TLE_RES_BITS 0x00ffffffffffff00UL
union topology_container {
	uint64_t raw;
	struct {
		uint8_t nl;
		uint8_t reserved[6];
		uint8_t id;
	};
};

union topology_entry {
	uint8_t nl;
	union topology_cpu cpu;
	union topology_container container;
};

#define CPU_TOPOLOGY_MAX_LEVEL 6
struct sysinfo_15_1_x {
	uint8_t reserved0[2];
	uint16_t length;
	uint8_t mag[CPU_TOPOLOGY_MAX_LEVEL];
	uint8_t reserved0a;
	uint8_t mnest;
	uint8_t reserved0c[4];
	union topology_entry tle[];
};

#endif  /* _S390X_STSI_H_ */
