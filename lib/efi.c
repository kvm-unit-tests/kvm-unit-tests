/*
 * EFI-related functions to set up and run test cases in EFI
 *
 * Copyright (c) 2021, SUSE, Varad Gautam <varad.gautam@suse.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include <linux/efi.h>

unsigned long __efiapi efi_main(efi_handle_t handle, efi_system_table_t *sys_tab);
efi_system_table_t *efi_system_table = NULL;

static void efi_free_pool(void *ptr)
{
	efi_bs_call(free_pool, ptr);
}

static efi_status_t efi_get_memory_map(struct efi_boot_memmap *map)
{
	efi_memory_desc_t *m = NULL;
	efi_status_t status;
	unsigned long key = 0, map_size = 0, desc_size = 0;

	status = efi_bs_call(get_memory_map, &map_size,
			     NULL, &key, &desc_size, NULL);
	if (status != EFI_BUFFER_TOO_SMALL || map_size == 0)
		goto out;

	/*
	 * Pad map_size with additional descriptors so we don't need to
	 * retry.
	 */
	map_size += 4 * desc_size;
	*map->buff_size = map_size;
	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA,
			     map_size, (void **)&m);
	if (status != EFI_SUCCESS)
		goto out;

	/* Get the map. */
	status = efi_bs_call(get_memory_map, &map_size,
			     m, &key, &desc_size, NULL);
	if (status != EFI_SUCCESS) {
		efi_free_pool(m);
		goto out;
	}

	*map->desc_size = desc_size;
	*map->map_size = map_size;
	*map->key_ptr = key;
out:
	*map->map = m;
	return status;
}

static efi_status_t efi_exit_boot_services(void *handle,
					   struct efi_boot_memmap *map)
{
	return efi_bs_call(exit_boot_services, handle, *map->key_ptr);
}

unsigned long __efiapi efi_main(efi_handle_t handle, efi_system_table_t *sys_tab)
{
	efi_system_table = sys_tab;

	return 0;
}
