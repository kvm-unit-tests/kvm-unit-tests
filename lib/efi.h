#ifndef _EFI_H_
#define _EFI_H_

/*
 * EFI-related functions.
 *
 * Copyright (c) 2021, Google Inc, Zixuan Wang <zixuanwang@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "linux/efi.h"
#include <elf.h>

/*
 * Define a GUID that we can use to to pass environment variables.
 *
 * For example, to set the variable var to the value val via the EFI shell:
 * # setvar env -guid 97ef3e03-7329-4a6a-b9ba-6c1fdcc5f823 -rt =L"val"
 */
#define EFI_VAR_GUID EFI_GUID(0x97ef3e03, 0x7329, 0x4a6a, 0xb9, 0xba, 0x6c, 0x1f, 0xdc, 0xc5, 0xf8, 0x23);

/* Names of environment variables we can handle */
#define ENV_VARNAME_DTBFILE L"fdtfile"

/*
 * efi_bootinfo_t: stores EFI-related machine info retrieved before exiting EFI
 * boot services, and is then used by setup_efi(). setup_efi() cannot retrieve
 * this info as it is called after ExitBootServices and thus some EFI resources
 * and functions are not available.
 */
typedef struct {
	struct efi_boot_memmap mem_map;
	const void *fdt;
} efi_bootinfo_t;

efi_status_t _relocate(long ldbase, Elf64_Dyn *dyn, efi_handle_t handle,
		       efi_system_table_t *sys_tab);
efi_status_t efi_get_memory_map(struct efi_boot_memmap *map);
efi_status_t efi_exit_boot_services(void *handle, struct efi_boot_memmap *map);
efi_status_t efi_get_system_config_table(efi_guid_t table_guid, void **table);
efi_status_t efi_main(efi_handle_t handle, efi_system_table_t *sys_tab);

#endif /* _EFI_H_ */
