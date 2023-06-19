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
#include <bitops.h>
#include <libcflat.h>
#include <sie.h>
#include <asm/page.h>
#include <libcflat.h>
#include <alloc_page.h>

void sie_expect_validity(struct vm *vm)
{
	vm->validity_expected = true;
}

uint16_t sie_get_validity(struct vm *vm)
{
	/*
	 * 0xffff will never be returned by SIE, so we can indicate a
	 * missing validity via this value.
	 */
	if (vm->sblk->icptcode != ICPT_VALIDITY)
		return 0xffff;

	return vm->sblk->ipb >> 16;
}

void sie_check_validity(struct vm *vm, uint16_t vir_exp)
{
	uint16_t vir = sie_get_validity(vm);

	report(vir_exp == vir, "VALIDITY: %x", vir);
}

void sie_handle_validity(struct vm *vm)
{
	if (vm->sblk->icptcode != ICPT_VALIDITY)
		return;

	if (!vm->validity_expected)
		report_abort("VALIDITY: %x", sie_get_validity(vm));
	vm->validity_expected = false;
}

void sie(struct vm *vm)
{
	if (vm->sblk->sdf == 2)
		memcpy(vm->sblk->pv_grregs, vm->save_area.guest.grs,
		       sizeof(vm->save_area.guest.grs));

	/* Reset icptcode so we don't trip over it below */
	vm->sblk->icptcode = 0;

	while (vm->sblk->icptcode == 0) {
		sie64a(vm->sblk, &vm->save_area);
		sie_handle_validity(vm);
	}
	vm->save_area.guest.grs[14] = vm->sblk->gg14;
	vm->save_area.guest.grs[15] = vm->sblk->gg15;

	if (vm->sblk->sdf == 2)
		memcpy(vm->save_area.guest.grs, vm->sblk->pv_grregs,
		       sizeof(vm->save_area.guest.grs));
}

void sie_guest_sca_create(struct vm *vm)
{
	vm->sca = (struct esca_block *)alloc_page();

	/* Let's start out with one page of ESCA for now */
	vm->sblk->scaoh = ((uint64_t)vm->sca >> 32);
	vm->sblk->scaol = (uint64_t)vm->sca & ~0x3fU;
	vm->sblk->ecb2 |= ECB2_ESCA;

	/* Enable SIGP sense running interpretation */
	vm->sblk->ecb |= ECB_SRSI;

	/* We assume that cpu 0 is always part of the vm */
	vm->sca->mcn[0] = BIT(63);
	vm->sca->cpu[0].sda = (uint64_t)vm->sblk;
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
	vm->guest_mem = (uint8_t *)guest_mem;
	/* For non-PV guests we re-use the host's ASCE for ease of use */
	vm->save_area.guest.asce = stctg(1);
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
	if (vm->sblk->ecb2 & ECB2_ESCA)
		free_page(vm->sca);
}
