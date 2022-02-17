/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Functions to retrieve VM-specific information
 *
 * Copyright (c) 2020 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 */

#include <libcflat.h>
#include <alloc_page.h>
#include <asm/arch_def.h>
#include "vm.h"
#include "stsi.h"

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

	if (stsi_get_fc() != 3) {
		initialized = true;
		return is_tcg;
	}

	buf = alloc_page();
	assert(buf);

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

/**
 * Detect whether we are running with KVM
 */
bool vm_is_kvm(void)
{
	/* EBCDIC for "KVM/" */
	const uint8_t kvm_ebcdic[] = { 0xd2, 0xe5, 0xd4, 0x61 };
	static bool initialized;
	static bool is_kvm;
	struct sysinfo_3_2_2 *stsi_322;

	if (initialized)
		return is_kvm;

	if (stsi_get_fc() != 3 || vm_is_tcg()) {
		initialized = true;
		return is_kvm;
	}

	stsi_322 = alloc_page();
	assert(stsi_322);

	if (stsi(stsi_322, 3, 2, 2))
		goto out;

	/*
	 * If the manufacturer string is "KVM/" in EBCDIC, then we
	 * are on KVM.
	 */
	is_kvm = !memcmp(&stsi_322->vm[0].cpi, kvm_ebcdic, sizeof(kvm_ebcdic));
	initialized = true;
out:
	free_page(stsi_322);
	return is_kvm;
}

bool vm_is_lpar(void)
{
	return stsi_get_fc() == 2;
}

