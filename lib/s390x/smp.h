/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x smp
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#ifndef _S390X_SMP_H_
#define _S390X_SMP_H_

#include <asm/arch_def.h>

struct cpu {
	struct lowcore *lowcore;
	uint64_t *stack;
	uint16_t addr;
	bool active;
};

struct cpu_status {
    uint64_t    fprs[16];                       /* 0x0000 */
    uint64_t    grs[16];                        /* 0x0080 */
    struct psw  psw;                            /* 0x0100 */
    uint8_t     pad_0x0110[0x0118 - 0x0110];    /* 0x0110 */
    uint32_t    prefix;                         /* 0x0118 */
    uint32_t    fpc;                            /* 0x011c */
    uint8_t     pad_0x0120[0x0124 - 0x0120];    /* 0x0120 */
    uint32_t    todpr;                          /* 0x0124 */
    uint64_t    cputm;                          /* 0x0128 */
    uint64_t    ckc;                            /* 0x0130 */
    uint8_t     pad_0x0138[0x0140 - 0x0138];    /* 0x0138 */
    uint32_t    ars[16];                        /* 0x0140 */
    uint64_t    crs[16];                        /* 0x0384 */
};

int smp_query_num_cpus(void);
struct cpu *smp_cpu_from_addr(uint16_t addr);
bool smp_cpu_stopped(uint16_t addr);
bool smp_sense_running_status(uint16_t addr);
int smp_cpu_restart(uint16_t addr);
int smp_cpu_start(uint16_t addr, struct psw psw);
int smp_cpu_stop(uint16_t addr);
int smp_cpu_stop_store_status(uint16_t addr);
int smp_cpu_destroy(uint16_t addr);
int smp_cpu_setup(uint16_t addr, struct psw psw);
void smp_teardown(void);
void smp_setup(void);

#endif
