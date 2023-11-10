/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Functions to retrieve information about the host system.
 *
 * Copyright (c) 2020 Red Hat Inc
 * Copyright 2022 IBM Corp.
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  Claudio Imbrenda <imbrenda@linux.ibm.com>
 */

#include <libcflat.h>
#include <alloc_page.h>
#include <asm/arch_def.h>
#include <asm/page.h>
#include "hardware.h"
#include "stsi.h"

/* The string "QEMU" in EBCDIC */
static const uint8_t qemu_ebcdic[] = { 0xd8, 0xc5, 0xd4, 0xe4 };
/* The string "KVM/" in EBCDIC */
static const uint8_t kvm_ebcdic[] = { 0xd2, 0xe5, 0xd4, 0x61 };

static enum s390_host do_detect_host(void)
{
	uint8_t buf[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
	struct sysinfo_3_2_2 *stsi_322 = (struct sysinfo_3_2_2 *)buf;

	if (stsi_get_fc() == 2)
		return HOST_IS_LPAR;

	if (stsi_get_fc() != 3)
		return HOST_IS_UNKNOWN;

	if (!stsi(buf, 1, 1, 1)) {
		/*
		 * If the manufacturer string is "QEMU" in EBCDIC, then we
		 * are on TCG (otherwise the string is "IBM" in EBCDIC)
		 */
		if (!memcmp((char *)buf + 32, qemu_ebcdic, sizeof(qemu_ebcdic)))
			return HOST_IS_TCG;
	}

	if (!stsi(buf, 3, 2, 2)) {
		/*
		 * If the manufacturer string is "KVM/" in EBCDIC, then we
		 * are on KVM.
		 */
		if (!memcmp(&stsi_322->vm[0].cpi, kvm_ebcdic, sizeof(kvm_ebcdic)))
			return HOST_IS_KVM;
	}

	return HOST_IS_UNKNOWN;
}

enum s390_host detect_host(void)
{
	static enum s390_host host = HOST_IS_UNKNOWN;
	static bool initialized = false;

	if (initialized)
		return host;

	host = do_detect_host();
	initialized = true;
	return host;
}
