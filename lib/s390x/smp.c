/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x smp
 * Based on Linux's arch/s390/kernel/smp.c and
 * arch/s390/include/asm/sigp.h
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <bitops.h>
#include <asm/arch_def.h>
#include <asm/sigp.h>
#include <asm/page.h>
#include <asm/barrier.h>
#include <asm/spinlock.h>
#include <asm/asm-offsets.h>

#include <alloc.h>
#include <alloc_page.h>

#include "smp.h"
#include "sclp.h"

static struct cpu *cpus;
static struct spinlock lock;

extern void smp_cpu_setup_state(void);

static void check_idx(uint16_t idx)
{
	assert(idx < smp_query_num_cpus());
}

int smp_query_num_cpus(void)
{
	return sclp_get_cpu_num();
}

struct lowcore *smp_get_lowcore(uint16_t idx)
{
	if (THIS_CPU->idx == idx)
		return &lowcore;

	check_idx(idx);
	return cpus[idx].lowcore;
}

int smp_sigp(uint16_t idx, uint8_t order, unsigned long parm, uint32_t *status)
{
	check_idx(idx);
	return sigp_retry(cpus[idx].addr, order, parm, status);
}

struct cpu *smp_cpu_from_addr(uint16_t addr)
{
	int i, num = smp_query_num_cpus();

	for (i = 0; i < num; i++) {
		if (cpus[i].addr == addr)
			return &cpus[i];
	}
	return NULL;
}

struct cpu *smp_cpu_from_idx(uint16_t idx)
{
	check_idx(idx);
	return &cpus[idx];
}

uint16_t smp_cpu_addr(uint16_t idx)
{
	check_idx(idx);
	return cpus[idx].addr;
}

bool smp_cpu_stopped(uint16_t idx)
{
	uint32_t status;

	if (smp_sigp(idx, SIGP_SENSE, 0, &status) != SIGP_CC_STATUS_STORED)
		return false;
	return !!(status & (SIGP_STATUS_CHECK_STOP|SIGP_STATUS_STOPPED));
}

bool smp_sense_running_status(uint16_t idx)
{
	if (smp_sigp(idx, SIGP_SENSE_RUNNING, 0, NULL) != SIGP_CC_STATUS_STORED)
		return true;
	/* Status stored condition code is equivalent to cpu not running. */
	return false;
}

static int smp_cpu_stop_nolock(uint16_t idx, bool store)
{
	uint8_t order = store ? SIGP_STOP_AND_STORE_STATUS : SIGP_STOP;

	/* refuse to work on the boot CPU */
	if (idx == 0)
		return -1;

	if (smp_sigp(idx, order, 0, NULL))
		return -1;

	while (!smp_cpu_stopped(idx))
		mb();
	/* idx has been already checked by the smp_* functions called above */
	cpus[idx].active = false;
	return 0;
}

int smp_cpu_stop(uint16_t idx)
{
	int rc;

	spin_lock(&lock);
	rc = smp_cpu_stop_nolock(idx, false);
	spin_unlock(&lock);
	return rc;
}

/*
 * Functionally equivalent to smp_cpu_stop(), but without the
 * elements that wait/serialize matters itself.
 * Used to see if KVM itself is serialized correctly.
 */
int smp_cpu_stop_nowait(uint16_t idx)
{
	check_idx(idx);

	/* refuse to work on the boot CPU */
	if (idx == 0)
		return -1;

	spin_lock(&lock);

	/* Don't suppress a CC2 with sigp_retry() */
	if (sigp(cpus[idx].addr, SIGP_STOP, 0, NULL)) {
		spin_unlock(&lock);
		return -1;
	}

	cpus[idx].active = false;
	spin_unlock(&lock);

	return 0;
}

int smp_cpu_stop_store_status(uint16_t idx)
{
	int rc;

	spin_lock(&lock);
	rc = smp_cpu_stop_nolock(idx, true);
	spin_unlock(&lock);
	return rc;
}

static int smp_cpu_restart_nolock(uint16_t idx, struct psw *psw)
{
	int rc;

	check_idx(idx);
	if (psw) {
		cpus[idx].lowcore->restart_new_psw.mask = psw->mask;
		cpus[idx].lowcore->restart_new_psw.addr = psw->addr;
	}
	/*
	 * Stop the cpu, so we don't have a race between a running cpu
	 * and the restart in the test that checks if the cpu is
	 * running after the restart.
	 */
	smp_cpu_stop_nolock(idx, false);
	rc = smp_sigp(idx, SIGP_RESTART, 0, NULL);
	if (rc)
		return rc;
	/*
	 * The order has been accepted, but the actual restart may not
	 * have been performed yet, so wait until the cpu is running.
	 */
	while (smp_cpu_stopped(idx))
		mb();
	cpus[idx].active = true;
	return 0;
}

int smp_cpu_restart(uint16_t idx)
{
	int rc;

	spin_lock(&lock);
	rc = smp_cpu_restart_nolock(idx, NULL);
	spin_unlock(&lock);
	return rc;
}

/*
 * Functionally equivalent to smp_cpu_restart(), but without the
 * elements that wait/serialize matters here in the test.
 * Used to see if KVM itself is serialized correctly.
 */
int smp_cpu_restart_nowait(uint16_t idx)
{
	check_idx(idx);

	spin_lock(&lock);

	/* Don't suppress a CC2 with sigp_retry() */
	if (sigp(cpus[idx].addr, SIGP_RESTART, 0, NULL)) {
		spin_unlock(&lock);
		return -1;
	}

	cpus[idx].active = true;

	spin_unlock(&lock);

	return 0;
}

int smp_cpu_start(uint16_t idx, struct psw psw)
{
	int rc;

	spin_lock(&lock);
	rc = smp_cpu_restart_nolock(idx, &psw);
	spin_unlock(&lock);
	return rc;
}

int smp_cpu_destroy(uint16_t idx)
{
	int rc;

	spin_lock(&lock);
	rc = smp_cpu_stop_nolock(idx, false);
	if (!rc) {
		free_pages(cpus[idx].lowcore);
		free_pages(cpus[idx].stack);
		cpus[idx].lowcore = (void *)-1UL;
		cpus[idx].stack = (void *)-1UL;
	}
	spin_unlock(&lock);
	return rc;
}

static int smp_cpu_setup_nolock(uint16_t idx, struct psw psw)
{
	struct lowcore *lc;

	if (cpus[idx].active)
		return -1;

	smp_sigp(idx, SIGP_INITIAL_CPU_RESET, 0, NULL);

	lc = alloc_pages_flags(1, AREA_DMA31);
	cpus[idx].lowcore = lc;
	smp_sigp(idx, SIGP_SET_PREFIX, (unsigned long )lc, NULL);

	/* Copy all exception psws. */
	memcpy(lc, cpus[0].lowcore, 512);
	lc->this_cpu = &cpus[idx];

	/* Setup stack */
	cpus[idx].stack = (uint64_t *)alloc_pages(2);

	/* Start without DAT and any other mask bits. */
	lc->sw_int_psw.mask = psw.mask;
	lc->sw_int_psw.addr = psw.addr;
	lc->sw_int_grs[14] = psw.addr;
	lc->sw_int_grs[15] = (uint64_t)cpus[idx].stack + (PAGE_SIZE * 4);
	lc->restart_new_psw.mask = PSW_MASK_64;
	lc->restart_new_psw.addr = (uint64_t)smp_cpu_setup_state;
	lc->sw_int_crs[0] = BIT_ULL(CTL0_AFP);

	/* Start processing */
	smp_cpu_restart_nolock(idx, NULL);
	/* Wait until the cpu has finished setup and started the provided psw */
	while (lc->restart_new_psw.addr != psw.addr)
		mb();

	return 0;
}

int smp_cpu_setup(uint16_t idx, struct psw psw)
{
	int rc = -1;

	spin_lock(&lock);
	if (cpus) {
		check_idx(idx);
		rc = smp_cpu_setup_nolock(idx, psw);
	}
	spin_unlock(&lock);
	return rc;
}

/*
 * Disregarding state, stop all cpus that once were online except for
 * calling cpu.
 */
void smp_teardown(void)
{
	int i = 0;
	uint16_t this_cpu = stap();
	int num = smp_query_num_cpus();

	spin_lock(&lock);
	for (; i < num; i++) {
		if (cpus[i].active &&
		    cpus[i].addr != this_cpu) {
			sigp_retry(cpus[i].addr, SIGP_STOP, 0, NULL);
		}
	}
	spin_unlock(&lock);
}

/*Expected to be called from boot cpu */
extern uint64_t *stackptr;
void smp_setup(void)
{
	int i = 0;
	int num = smp_query_num_cpus();
	unsigned short cpu0_addr = stap();
	struct CPUEntry *entry = sclp_get_cpu_entries();

	spin_lock(&lock);
	if (num > 1)
		printf("SMP: Initializing, found %d cpus\n", num);

	cpus = calloc(num, sizeof(*cpus));
	for (i = 0; i < num; i++) {
		cpus[i].addr = entry[i].address;
		cpus[i].active = false;
		cpus[i].idx = i;
		/*
		 * Fill in the boot CPU. If the boot CPU is not at index 0,
		 * swap it with the one at index 0. This guarantees that the
		 * boot CPU will always have index 0. If the boot CPU was
		 * already at index 0, a few extra useless assignments are
		 * performed, but everything will work ok.
		 * Notice that there is no guarantee that the list of CPUs
		 * returned by the Read SCP Info command is in any
		 * particular order, or that its order will stay consistent
		 * across multiple invocations.
		 */
		if (entry[i].address == cpu0_addr) {
			cpus[i].addr = cpus[0].addr;
			cpus[0].addr = cpu0_addr;
			cpus[0].stack = stackptr;
			cpus[0].lowcore = (void *)0;
			cpus[0].active = true;
			THIS_CPU = &cpus[0];
		}
	}
	spin_unlock(&lock);
}
