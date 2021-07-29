/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Library for managing various aspects of guests
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */

#include <asm/barrier.h>
#include <libcflat.h>
#include <sie.h>
#include <asm/page.h>
#include <libcflat.h>
#include <alloc_page.h>

static bool validity_expected;
static uint16_t vir;		/* Validity interception reason */

void sie_expect_validity(void)
{
	validity_expected = true;
	vir = 0;
}

void sie_check_validity(uint16_t vir_exp)
{
	report(vir_exp == vir, "VALIDITY: %x", vir);
	vir = 0;
}

void sie_handle_validity(struct vm *vm)
{
	if (vm->sblk->icptcode != ICPT_VALIDITY)
		return;

	vir = vm->sblk->ipb >> 16;

	if (!validity_expected)
		report_abort("VALIDITY: %x", vir);
	validity_expected = false;
}

void sie(struct vm *vm)
{
	/* Reset icptcode so we don't trip over it below */
	vm->sblk->icptcode = 0;

	while (vm->sblk->icptcode == 0) {
		sie64a(vm->sblk, &vm->save_area);
		sie_handle_validity(vm);
	}
	vm->save_area.guest.grs[14] = vm->sblk->gg14;
	vm->save_area.guest.grs[15] = vm->sblk->gg15;
}

/* Initializes the struct vm members like the SIE control block. */
void sie_guest_create(struct vm *vm, uint64_t guest_mem, uint64_t guest_mem_len)
{
	vm->sblk = alloc_page();
	memset(vm->sblk, 0, PAGE_SIZE);
	vm->sblk->cpuflags = CPUSTAT_ZARCH | CPUSTAT_RUNNING;
	vm->sblk->ihcpu = 0xffff;
	vm->sblk->prefix = 0;

	/* Guest memory chunks are always 1MB */
	assert(!(guest_mem_len & ~HPAGE_MASK));
	/* Currently MSO/MSL is the easiest option */
	vm->sblk->mso = (uint64_t)guest_mem;
	vm->sblk->msl = (uint64_t)guest_mem + ((guest_mem_len - 1) & HPAGE_MASK);

	/* CRYCB needs to be in the first 2GB */
	vm->crycb = alloc_pages_flags(0, AREA_DMA31);
	vm->sblk->crycbd = (uint32_t)(uintptr_t)vm->crycb;
}

/* Frees the memory that was gathered on initialization */
void sie_guest_destroy(struct vm *vm)
{
	free_page(vm->crycb);
	free_page(vm->sblk);
}
