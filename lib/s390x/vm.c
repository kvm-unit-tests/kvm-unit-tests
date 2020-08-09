/*
 * Functions to retrieve VM-specific information
 *
 * Copyright (c) 2020 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <libcflat.h>
#include <alloc_page.h>
#include <asm/arch_def.h>
#include "vm.h"

/**
 * Detect whether we are running with TCG (instead of KVM)
 */
bool vm_is_tcg(void)
{
	const char qemu_ebcdic[] = { 0xd8, 0xc5, 0xd4, 0xe4 };
	static bool initialized = false;
	static bool is_tcg = false;
	uint8_t *buf;

	if (initialized)
		return is_tcg;

	buf = alloc_page();
	if (!buf)
		return false;

	if (stsi(buf, 1, 1, 1))
		goto out;

	/*
	 * If the manufacturer string is "QEMU" in EBCDIC, then we
	 * are on TCG (otherwise the string is "IBM" in EBCDIC)
	 */
	is_tcg = !memcmp(&buf[32], qemu_ebcdic, sizeof(qemu_ebcdic));
	initialized = true;
out:
	free_page(buf);
	return is_tcg;
}
