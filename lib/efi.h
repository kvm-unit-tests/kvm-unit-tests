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
 * efi_bootinfo_t: stores EFI-related machine info retrieved before exiting EFI
 * boot services, and is then used by setup_efi(). setup_efi() cannot retrieve
 * this info as it is called after ExitBootServices and thus some EFI resources
 * and functions are not available.
 */
typedef struct {
	struct efi_boot_memmap mem_map;
} efi_bootinfo_t;

efi_status_t _relocate(long ldbase, Elf64_Dyn *dyn, efi_handle_t handle,
		       efi_system_table_t *sys_tab);
efi_status_t efi_get_memory_map(struct efi_boot_memmap *map);
efi_status_t efi_exit_boot_services(void *handle, struct efi_boot_memmap *map);
efi_status_t efi_get_system_config_table(efi_guid_t table_guid, void **table);
efi_status_t efi_main(efi_handle_t handle, efi_system_table_t *sys_tab);

#endif /* _EFI_H_ */
