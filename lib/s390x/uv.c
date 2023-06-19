/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Ultravisor related functionality
 *
 * Copyright 2020 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <bitops.h>
#include <alloc.h>
#include <alloc_page.h>
#include <asm/page.h>
#include <asm/arch_def.h>

#include <asm/facility.h>
#include <asm/uv.h>
#include <uv.h>
#include <sie.h>
#include <snippet.h>

static struct uv_cb_qui uvcb_qui = {
	.header.cmd = UVC_CMD_QUI,
	.header.len = sizeof(uvcb_qui),
};
static uint64_t uv_init_mem;


bool uv_os_is_guest(void)
{
	return test_facility(158) &&
		uv_query_test_call(BIT_UVC_CMD_SET_SHARED_ACCESS) &&
		uv_query_test_call(BIT_UVC_CMD_REMOVE_SHARED_ACCESS);
}

bool uv_os_is_host(void)
{
	return test_facility(158) && uv_query_test_call(BIT_UVC_CMD_INIT_UV);
}

bool uv_host_requirement_checks(void)
{
	if (!test_facility(158)) {
		report_skip("UV Call facility unavailable");
		return false;
	}
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		return false;
	}
	if (get_ram_size() < SNIPPET_PV_MIN_MEM_SIZE) {
		report_skip("Not enough memory. This test needs about %ld MB of memory",
			    SNIPPET_PV_MIN_MEM_SIZE / SZ_1M);
		return false;
	}

	return true;
}

bool uv_query_test_call(unsigned int nr)
{
	/* Query needs to be called first */
	assert(uvcb_qui.header.rc);
	assert(nr < BITS_PER_LONG * ARRAY_SIZE(uvcb_qui.inst_calls_list));

	return test_bit_inv(nr, uvcb_qui.inst_calls_list);
}

const struct uv_cb_qui *uv_get_query_data(void)
{
	/* Query needs to be called first */
	assert(uvcb_qui.header.rc == 1 || uvcb_qui.header.rc == 0x100);

	return &uvcb_qui;
}

int uv_setup(void)
{
	if (!test_facility(158))
		return 0;

	uv_call(0, (u64)&uvcb_qui);

	assert(uvcb_qui.header.rc == 1 || uvcb_qui.header.rc == 0x100);
	return 1;
}

void uv_init(void)
{
	struct uv_cb_init uvcb_init = {
		.header.len = sizeof(uvcb_init),
		.header.cmd = UVC_CMD_INIT_UV,
	};
	static bool initialized;
	int cc;

	/* Let's not do this twice */
	if (initialized)
		return;
	/* Query is done on initialization but let's check anyway */
	assert(uvcb_qui.header.rc == 1 || uvcb_qui.header.rc == 0x100);

	/* Donated storage needs to be over 2GB aligned to 1MB */
	uv_init_mem = (uint64_t)memalign_pages_flags(HPAGE_SIZE, uvcb_qui.uv_base_stor_len, AREA_NORMAL);
	uvcb_init.stor_origin = uv_init_mem;
	uvcb_init.stor_len = uvcb_qui.uv_base_stor_len;

	cc = uv_call(0, (uint64_t)&uvcb_init);
	assert(cc == 0);
	initialized = true;
}

/*
 * Create a new ASCE for the UV config because they can't be shared
 * for security reasons. We just simply copy the top most table into a
 * fresh set of allocated pages and use those pages as the asce.
 */
static uint64_t create_asce(void)
{
	void *pgd_new, *pgd_old;
	uint64_t asce = stctg(1);

	pgd_new = memalign_pages(PAGE_SIZE, PAGE_SIZE * 4);
	pgd_old = (void *)(asce & PAGE_MASK);

	memcpy(pgd_new, pgd_old, PAGE_SIZE * 4);

	asce = __pa(pgd_new) | ASCE_P | (asce & (ASCE_DT | ASCE_TL));
	return asce;
}

void uv_create_guest(struct vm *vm)
{
	struct uv_cb_cgc uvcb_cgc = {
		.header.cmd = UVC_CMD_CREATE_SEC_CONF,
		.header.len = sizeof(uvcb_cgc),
	};
	struct uv_cb_csc uvcb_csc = {
		.header.len = sizeof(uvcb_csc),
		.header.cmd = UVC_CMD_CREATE_SEC_CPU,
		.state_origin = (uint64_t)vm->sblk,
		.num = 0,
	};
	unsigned long vsize;
	int cc;

	uvcb_cgc.guest_stor_origin = vm->sblk->mso;
	uvcb_cgc.guest_stor_len = vm->sblk->msl;

	/* Config allocation */
	vsize = uvcb_qui.conf_base_virt_stor_len +
		((uvcb_cgc.guest_stor_len / HPAGE_SIZE) * uvcb_qui.conf_virt_var_stor_len);

	vm->uv.conf_base_stor = memalign_pages_flags(PAGE_SIZE * 4, uvcb_qui.conf_base_phys_stor_len, 0);
	/*
	 * This allocation needs to be below the max guest storage
	 * address so let's simply put it into the physical memory
	 */
	vm->uv.conf_var_stor = memalign_pages_flags(PAGE_SIZE, vsize,0);
	uvcb_cgc.conf_base_stor_origin = (uint64_t)vm->uv.conf_base_stor;
	uvcb_cgc.conf_var_stor_origin = (uint64_t)vm->uv.conf_var_stor;

	/* CPU allocation */
	vm->uv.cpu_stor = memalign_pages_flags(PAGE_SIZE, uvcb_qui.cpu_stor_len, 0);
	uvcb_csc.stor_origin = (uint64_t)vm->uv.cpu_stor;

	uvcb_cgc.guest_asce = create_asce();
	vm->save_area.guest.asce = uvcb_cgc.guest_asce;
	uvcb_cgc.guest_sca = (uint64_t)vm->sca;

	cc = uv_call(0, (uint64_t)&uvcb_cgc);
	assert(!cc);

	vm->uv.vm_handle = uvcb_cgc.guest_handle;
	uvcb_csc.guest_handle = uvcb_cgc.guest_handle;
	cc = uv_call(0, (uint64_t)&uvcb_csc);
	vm->uv.vcpu_handle = uvcb_csc.cpu_handle;
	assert(!cc);

	/*
	 * Convert guest to format 4:
	 *
	 *  - Set format 4
	 *  - Write UV handles into sblk
	 *  - Allocate and set SIDA
	 */
	vm->sblk->sdf = 2;
	vm->sblk->sidad = (uint64_t)alloc_page();
	vm->sblk->pv_handle_cpu = uvcb_csc.cpu_handle;
	vm->sblk->pv_handle_config = uvcb_cgc.guest_handle;
}

void uv_destroy_guest(struct vm *vm)
{
	int cc;
	u16 rc, rrc;

	cc = uv_cmd_nodata(vm->sblk->pv_handle_cpu,
			   UVC_CMD_DESTROY_SEC_CPU, &rc, &rrc);
	assert(cc == 0);
	free_page((void *)vm->sblk->sidad);
	free_pages(vm->uv.cpu_stor);

	cc = uv_cmd_nodata(vm->sblk->pv_handle_config,
			   UVC_CMD_DESTROY_SEC_CONF, &rc, &rrc);
	assert(cc == 0);
	free_pages(vm->uv.conf_base_stor);
	free_pages(vm->uv.conf_var_stor);

	free_pages((void *)(vm->uv.asce & PAGE_MASK));
	memset(&vm->uv, 0, sizeof(vm->uv));

	/* Convert the sblk back to non-PV */
	vm->save_area.guest.asce = stctg(1);
	vm->sblk->sdf = 0;
	vm->sblk->sidad = 0;
	vm->sblk->pv_handle_cpu = 0;
	vm->sblk->pv_handle_config = 0;
}

int uv_unpack(struct vm *vm, uint64_t addr, uint64_t len, uint64_t tweak)
{
	int i, cc;

	for (i = 0; i < len / PAGE_SIZE; i++) {
		cc = uv_unp_page(vm->uv.vm_handle, addr, tweak, i * PAGE_SIZE);
		assert(!cc);
		addr += PAGE_SIZE;
	}
	return cc;
}

void uv_verify_load(struct vm *vm)
{
	uint16_t rc, rrc;
	int cc;

	cc = uv_cmd_nodata(vm->uv.vm_handle, UVC_CMD_VERIFY_IMG, &rc, &rrc);
	assert(!cc);
	cc = uv_set_cpu_state(vm->uv.vcpu_handle, PV_CPU_STATE_OPR_LOAD);
	assert(!cc);
}
