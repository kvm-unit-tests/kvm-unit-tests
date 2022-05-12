/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Guarded storage related definitions
 *
 * Copyright 2018 IBM Corp.
 *
 * Authors:
 *    Martin Schwidefsky <schwidefsky@de.ibm.com>
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#include <stdint.h>

#ifndef _S390X_GS_H_
#define _S390X_GS_H_

struct gs_cb {
	uint64_t reserved;
	uint64_t gsd;
	uint64_t gssm;
	uint64_t gs_epl_a;
};

struct gs_epl {
	uint8_t pad1;
	union {
		uint8_t gs_eam;
		struct {
			uint8_t		: 6;
			uint8_t e	: 1;
			uint8_t b	: 1;
		};
	};
	union {
		uint8_t gs_eci;
		struct {
			uint8_t tx	: 1;
			uint8_t cx	: 1;
			uint8_t		: 5;
			uint8_t in	: 1;
		};
	};
	union {
		uint8_t gs_eai;
		struct {
			uint8_t		: 1;
			uint8_t t	: 1;
			uint8_t as	: 2;
			uint8_t ar	: 4;
		};
	};
	uint32_t pad2;
	uint64_t gs_eha;
	uint64_t gs_eia;
	uint64_t gs_eoa;
	uint64_t gs_eir;
	uint64_t gs_era;
};

static inline void load_gs_cb(struct gs_cb *gs_cb)
{
	asm volatile(".insn rxy,0xe3000000004d,0,%0" : : "Q" (*gs_cb));
}

static inline void store_gs_cb(struct gs_cb *gs_cb)
{
	asm volatile(".insn rxy,0xe30000000049,0,%0" : : "Q" (*gs_cb));
}

#endif
