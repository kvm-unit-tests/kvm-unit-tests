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
#include <asm/interrupt.h>
#include <libcflat.h>
#include <alloc_page.h>
#include <vmalloc.h>
#include <sclp.h>

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
	uint64_t old_cr13;

	/* When a pgm int code is set, we'll never enter SIE below. */
	assert(!read_pgm_int_code());

	if (vm->sblk->sdf == 2)
		memcpy(vm->sblk->pv_grregs, vm->save_area.guest.grs,
		       sizeof(vm->save_area.guest.grs));

	/* Reset icptcode so we don't trip over it below */
	vm->sblk->icptcode = 0;

	/*
	 * Set up home address space to match primary space. Instead of running
	 * in home space all the time, we switch every time in sie() because:
	 * - tests that depend on running in primary space mode don't need to be
	 *   touched
	 * - it avoids regressions in tests
	 * - switching every time makes it easier to extend this in the future,
	 *   for example to allow tests to run in whatever space they want
	 */
	old_cr13 = stctg(13);
	lctlg(13, stctg(1));

	/* switch to home space so guest tables can be different from host */
	psw_mask_set_bits(PSW_MASK_HOME);

	/* also handle all interruptions in home space while in SIE */
	irq_set_dat_mode(true, AS_HOME);

	/* leave SIE when we have an intercept or an interrupt so the test can react to it */
	while (vm->sblk->icptcode == 0 && !read_pgm_int_code()) {
		sie64a(vm->sblk, &vm->save_area);
		sie_handle_validity(vm);
	}
	vm->save_area.guest.grs[14] = vm->sblk->gg14;
	vm->save_area.guest.grs[15] = vm->sblk->gg15;

	irq_set_dat_mode(true, AS_PRIM);
	psw_mask_clear_bits(PSW_MASK_HOME);

	/* restore the old CR 13 */
	lctlg(13, old_cr13);

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

/**
 * sie_guest_alloc() - Allocate memory for a guest and map it in virtual address
 * space such that it is properly aligned.
 * @guest_size: the desired size of the guest in bytes.
 */
uint8_t *sie_guest_alloc(uint64_t guest_size)
{
	static unsigned long guest_counter = 1;
	u8 *guest_phys, *guest_virt;
	unsigned long i;
	pgd_t *root;

	setup_vm();
	root = (pgd_t *)(stctg(1) & PAGE_MASK);

	/*
	 * Start of guest memory in host virtual space needs to be aligned to
	 * 2GB for some environments. It also can't be at 2GB since the memory
	 * allocator stores its page_states metadata there.
	 * Thus we use the next multiple of 4GB after the end of physical
	 * mapping. This also leaves space after end of physical memory so the
	 * page immediately after physical memory is guaranteed not to be
	 * present.
	 */
	guest_virt = (uint8_t *)ALIGN(get_ram_size() + guest_counter * 4UL * SZ_1G, SZ_2G);
	guest_counter++;

	guest_phys = alloc_pages(get_order(guest_size) - 12);
	/*
	 * Establish a new mapping of the guest memory so it can be 2GB aligned
	 * without actually requiring 2GB physical memory.
	 */
	for (i = 0; i < guest_size; i += PAGE_SIZE) {
		install_page(root, __pa(guest_phys + i), guest_virt + i);
	}
	memset(guest_virt, 0, guest_size);

	return guest_virt;
}

/* Frees the memory that was gathered on initialization */
void sie_guest_destroy(struct vm *vm)
{
	free_page(vm->crycb);
	free_page(vm->sblk);
	if (vm->sblk->ecb2 & ECB2_ESCA)
		free_page(vm->sca);
}
