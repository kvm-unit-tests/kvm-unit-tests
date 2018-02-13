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
#include "sclp.h"
#include <alloc_phys.h>

extern unsigned long stacktop;

static uint64_t storage_increment_size;
static uint64_t max_ram_size;
static uint64_t ram_size;

static void mem_init(phys_addr_t mem_end)
{
	phys_addr_t freemem_start = (phys_addr_t)&stacktop;

	phys_alloc_init(freemem_start, mem_end - freemem_start);
}

void sclp_memory_setup(void)
{
	ReadInfo *ri = (void *)_sccb;
	uint64_t rnmax, rnsize;
	int cc;

	ri->h.length = SCCB_SIZE;
	sclp_service_call(SCLP_CMDW_READ_SCP_INFO_FORCED, ri);

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
