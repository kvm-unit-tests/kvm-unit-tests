/*
 * AMD SEV support in kvm-unit-tests
 *
 * Copyright (c) 2021, Google Inc
 *
 * Authors:
 *   Zixuan Wang <zixuanwang@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef _X86_AMD_SEV_H_
#define _X86_AMD_SEV_H_

#ifdef CONFIG_EFI

#include "libcflat.h"
#include "desc.h"
#include "asm/page.h"
#include "efi.h"

bool amd_sev_enabled(void);
efi_status_t setup_amd_sev(void);

bool amd_sev_es_enabled(void);
efi_status_t setup_amd_sev_es(void);
void setup_ghcb_pte(pgd_t *page_table);

unsigned long long get_amd_sev_c_bit_mask(void);
unsigned long long get_amd_sev_addr_upperbound(void);

#endif /* CONFIG_EFI */

#endif /* _X86_AMD_SEV_H_ */
