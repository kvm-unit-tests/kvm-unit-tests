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

static struct uv_cb_qui uvcb_qui = {
	.header.cmd = UVC_CMD_QUI,
	.header.len = sizeof(uvcb_qui),
};

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

bool uv_query_test_call(unsigned int nr)
{
	/* Query needs to be called first */
	assert(uvcb_qui.header.rc);
	assert(nr < BITS_PER_LONG * ARRAY_SIZE(uvcb_qui.inst_calls_list));

	return test_bit_inv(nr, uvcb_qui.inst_calls_list);
}

int uv_setup(void)
{
	if (!test_facility(158))
		return 0;

	uv_call(0, (u64)&uvcb_qui);

	assert(uvcb_qui.header.rc == 1 || uvcb_qui.header.rc == 0x100);
	return 1;
}
