/*
 * s390x SCLP driver
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <libcflat.h>
#include <asm/page.h>
#include <asm/arch_def.h>
#include <asm/interrupt.h>
#include <asm/barrier.h>
#include <asm/spinlock.h>
#include "sclp.h"
#include <alloc_phys.h>
#include <alloc_page.h>

extern unsigned long stacktop;

static uint64_t storage_increment_size;
static uint64_t max_ram_size;
static uint64_t ram_size;

char _sccb[PAGE_SIZE] __attribute__((__aligned__(4096)));
static volatile bool sclp_busy;
static struct spinlock sclp_lock;

static void mem_init(phys_addr_t mem_end)
{
	phys_addr_t freemem_start = (phys_addr_t)&stacktop;
	phys_addr_t base, top;

	phys_alloc_init(freemem_start, mem_end - freemem_start);
	phys_alloc_get_unused(&base, &top);
	base = (base + PAGE_SIZE - 1) & -PAGE_SIZE;
	top = top & -PAGE_SIZE;

	/* Make the pages available to the physical allocator */
	free_pages((void *)(unsigned long)base, top - base);
	page_alloc_ops_enable();
}

void sclp_setup_int(void)
{
	uint64_t mask;

	ctl_set_bit(0, 9);

	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
}

void sclp_handle_ext(void)
{
	ctl_clear_bit(0, 9);
	spin_lock(&sclp_lock);
	sclp_busy = false;
	spin_unlock(&sclp_lock);
}

void sclp_wait_busy(void)
{
	while (sclp_busy)
		mb();
}

void sclp_mark_busy(void)
{
	/*
	 * With multiple CPUs we might need to wait for another CPU's
	 * request before grabbing the busy indication.
	 */
	while (true) {
		sclp_wait_busy();
		spin_lock(&sclp_lock);
		if (!sclp_busy) {
			sclp_busy = true;
			spin_unlock(&sclp_lock);
			return;
		}
		spin_unlock(&sclp_lock);
	}
}

static void sclp_read_scp_info(ReadInfo *ri, int length)
{
	unsigned int commands[] = { SCLP_CMDW_READ_SCP_INFO_FORCED,
				    SCLP_CMDW_READ_SCP_INFO };
	int i, cc;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		sclp_mark_busy();
		memset(&ri->h, 0, sizeof(ri->h));
		ri->h.length = length;

		cc = sclp_service_call(commands[i], ri);
		if (cc)
			break;
		if (ri->h.response_code == SCLP_RC_NORMAL_READ_COMPLETION)
			return;
		if (ri->h.response_code != SCLP_RC_INVALID_SCLP_COMMAND)
			break;
	}
	report_abort("READ_SCP_INFO failed");
}

/* Perform service call. Return 0 on success, non-zero otherwise. */
int sclp_service_call(unsigned int command, void *sccb)
{
	int cc;

	sclp_setup_int();
	asm volatile(
		"       .insn   rre,0xb2200000,%1,%2\n"  /* servc %1,%2 */
		"       ipm     %0\n"
		"       srl     %0,28"
		: "=&d" (cc) : "d" (command), "a" (__pa(sccb))
		: "cc", "memory");
	sclp_wait_busy();
	if (cc == 3)
		return -1;
	if (cc == 2)
		return -1;
	return 0;
}

void sclp_memory_setup(void)
{
	ReadInfo *ri = (void *)_sccb;
	uint64_t rnmax, rnsize;
	int cc;

	sclp_read_scp_info(ri, SCCB_SIZE);

	/* calculate the storage increment size */
	rnsize = ri->rnsize;
	if (!rnsize) {
		rnsize = ri->rnsize2;
	}
	storage_increment_size = rnsize << 20;

	/* calculate the maximum memory size */
	rnmax = ri->rnmax;
	if (!rnmax) {
		rnmax = ri->rnmax2;
	}
	max_ram_size = rnmax * storage_increment_size;

	/* lowcore is always accessible, so the first increment is accessible */
	ram_size = storage_increment_size;

	/* probe for r/w memory up to max memory size */
	while (ram_size < max_ram_size) {
		expect_pgm_int();
		cc = tprot(ram_size + storage_increment_size - 1);
		/* stop once we receive an exception or have protected memory */
		if (clear_pgm_int() || cc != 0)
			break;
		ram_size += storage_increment_size;
	}

	mem_init(ram_size);
}

uint64_t get_ram_size(void)
{
	return ram_size;
}

uint64_t get_max_ram_size(void)
{
	return max_ram_size;
}
