/*
 * EFI-related functions to set up and run test cases in EFI
 *
 * Copyright (c) 2021, SUSE, Varad Gautam <varad.gautam@suse.com>
 * Copyright (c) 2021, Google Inc, Zixuan Wang <zixuanwang@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include <libcflat.h>
#include <argv.h>
#include <ctype.h>
#include <stdlib.h>
#include <asm/setup.h>
#include "efi.h"
#include "libfdt/libfdt.h"

/* From each arch */
extern char *initrd;
extern u32 initrd_size;

/* From lib/argv.c */
extern int __argc, __envc;
extern char *__argv[100];
extern char *__environ[200];

extern char _text;

extern int main(int argc, char **argv, char **envp);

efi_system_table_t *efi_system_table = NULL;

#ifdef __riscv
#define RISCV_EFI_BOOT_PROTOCOL_GUID EFI_GUID(0xccd15fec, 0x6f73, 0x4eec,  0x83, 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf)

unsigned long boot_hartid;

struct riscv_efi_boot_protocol {
	u64 revision;
	efi_status_t (*get_boot_hartid)(struct riscv_efi_boot_protocol *,
		      unsigned long *boot_hartid);
};

static efi_status_t efi_get_boot_hartid(void)
{
	efi_guid_t boot_protocol_guid = RISCV_EFI_BOOT_PROTOCOL_GUID;
	struct riscv_efi_boot_protocol *boot_protocol;
	efi_status_t status;

	status = efi_bs_call(locate_protocol, &boot_protocol_guid, NULL,
			     (void **)&boot_protocol);
	if (status != EFI_SUCCESS)
		return status;
	return efi_call_proto(boot_protocol, get_boot_hartid, &boot_hartid);
}
#endif

static void efi_free_pool(void *ptr)
{
	efi_bs_call(free_pool, ptr);
}

efi_status_t efi_get_memory_map(struct efi_boot_memmap *map)
{
	efi_memory_desc_t *m = NULL;
	efi_status_t status;
	unsigned long key = 0, map_size = 0, desc_size = 0;
	u32 desc_ver;

	status = efi_bs_call(get_memory_map, &map_size,
			     NULL, &key, &desc_size, &desc_ver);
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
			     m, &key, &desc_size, &desc_ver);
	if (status != EFI_SUCCESS) {
		efi_free_pool(m);
		goto out;
	}

	*map->desc_ver = desc_ver;
	*map->desc_size = desc_size;
	*map->map_size = map_size;
	*map->key_ptr = key;
out:
	*map->map = m;
	return status;
}

efi_status_t efi_exit_boot_services(void *handle, struct efi_boot_memmap *map)
{
	return efi_bs_call(exit_boot_services, handle, *map->key_ptr);
}

efi_status_t efi_get_system_config_table(efi_guid_t table_guid, void **table)
{
	size_t i;
	efi_config_table_t *tables;

	tables = (efi_config_table_t *)efi_system_table->tables;
	for (i = 0; i < efi_system_table->nr_tables; i++) {
		if (!memcmp(&table_guid, &tables[i].guid, sizeof(efi_guid_t))) {
			*table = tables[i].table;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

static void efi_exit(efi_status_t code)
{
	exit(code);

	/*
	 * Fallback to UEFI reset_system() service, in case testdev is
	 * missing and exit() does not properly exit.
	 */
	efi_rs_call(reset_system, EFI_RESET_SHUTDOWN, code, 0, NULL);
}

/* Adapted from drivers/firmware/efi/libstub/efi-stub.c */
static char *efi_convert_cmdline(struct efi_loaded_image_64 *image, int *cmd_line_len)
{
	const u16 *s2;
	unsigned long cmdline_addr = 0;
	int options_chars = image->load_options_size;
	const u16 *options = image->load_options;
	int options_bytes = 0, safe_options_bytes = 0;  /* UTF-8 bytes */
	bool in_quote = false;
	efi_status_t status;
	const int COMMAND_LINE_SIZE = 2048;

	if (options) {
		s2 = options;
		while (options_bytes < COMMAND_LINE_SIZE && options_chars--) {
			u16 c = *s2++;

			if (c < 0x80) {
				if (c == L'\0' || c == L'\n')
					break;
				if (c == L'"')
					in_quote = !in_quote;
				else if (!in_quote && isspace((char)c))
					safe_options_bytes = options_bytes;

				options_bytes++;
				continue;
			}

			/*
			 * Get the number of UTF-8 bytes corresponding to a
			 * UTF-16 character.
			 * The first part handles everything in the BMP.
			 */
			options_bytes += 2 + (c >= 0x800);
			/*
			 * Add one more byte for valid surrogate pairs. Invalid
			 * surrogates will be replaced with 0xfffd and take up
			 * only 3 bytes.
			 */
			if ((c & 0xfc00) == 0xd800) {
				/*
				 * If the very last word is a high surrogate,
				 * we must ignore it since we can't access the
				 * low surrogate.
				 */
				if (!options_chars) {
					options_bytes -= 3;
				} else if ((*s2 & 0xfc00) == 0xdc00) {
					options_bytes++;
					options_chars--;
					s2++;
				}
			}
		}
		if (options_bytes >= COMMAND_LINE_SIZE) {
			options_bytes = safe_options_bytes;
			printf("Command line is too long: truncated to %d bytes\n",
			       options_bytes);
		}
	}

	options_bytes++;        /* NUL termination */

	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, options_bytes, (void **)&cmdline_addr);
	if (status != EFI_SUCCESS)
		return NULL;

	snprintf((char *)cmdline_addr, options_bytes, "%.*ls", options_bytes - 1, options);

	*cmd_line_len = options_bytes;
	return (char *)cmdline_addr;
}

#if defined(__aarch64__) || defined(__riscv)
/*
 * Open the file and read it into a buffer.
 */
static void efi_load_image(efi_handle_t handle, struct efi_loaded_image_64 *image, void **data,
			   int *datasize, efi_char16_t *path_name)
{
	uint64_t buffer_size = sizeof(efi_file_info_t);
	efi_file_info_t *file_info;
	efi_file_io_interface_t *io_if;
	efi_file_t *root, *file;
	efi_status_t status;
	efi_guid_t file_system_proto_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
	efi_guid_t file_info_guid = EFI_FILE_INFO_ID;

	/* Open the device */
	status = efi_bs_call(handle_protocol, image->device_handle, &file_system_proto_guid,
			     (void **)&io_if);
	if (status != EFI_SUCCESS)
		return;

	status = io_if->open_volume(io_if, &root);
	if (status != EFI_SUCCESS)
		return;

	/* And then open the file */
	status = root->open(root, &file, path_name, EFI_FILE_MODE_READ, 0);
	if (status != EFI_SUCCESS) {
		printf("Failed to open %ls - %lx\n", path_name, status);
		assert(status == EFI_SUCCESS);
	}

	/* Find the file size in order to allocate the buffer */
	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, buffer_size, (void **)&file_info);
	if (status != EFI_SUCCESS)
		return;

	status = file->get_info(file, &file_info_guid, &buffer_size, file_info);
	if (status == EFI_BUFFER_TOO_SMALL) {
		efi_free_pool(file_info);
		status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, buffer_size, (void **)&file_info);
		assert(file_info);
		status = file->get_info(file, &file_info_guid, &buffer_size, file_info);
	}
	assert(status == EFI_SUCCESS);

	buffer_size = file_info->file_size;

	efi_free_pool(file_info);

	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, buffer_size, (void **)data);
	assert(*data);
	/* Perform the actual read */
	status = file->read(file, &buffer_size, *data);
	if (status == EFI_BUFFER_TOO_SMALL) {
		efi_free_pool(*data);
		status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, buffer_size, (void **)data);
		status = file->read(file, &buffer_size, *data);
	}
	assert(status == EFI_SUCCESS);

	*datasize = buffer_size;
}

static int efi_grow_buffer(efi_status_t *status, void **buffer, uint64_t buffer_size)
{
	int try_again;

	if (!*buffer && buffer_size) {
		*status = EFI_BUFFER_TOO_SMALL;
	}

	try_again = 0;
	if (*status == EFI_BUFFER_TOO_SMALL) {
		if (*buffer)
			efi_free_pool(*buffer);

		efi_bs_call(allocate_pool, EFI_LOADER_DATA, buffer_size, buffer);
		if (*buffer) {
			try_again = 1;
		} else {
			*status = EFI_OUT_OF_RESOURCES;
		}
	}

	if (!try_again && EFI_ERROR(*status) && *buffer) {
		efi_free_pool(*buffer);
		*buffer = NULL;
	}

	return try_again;
}

static void* efi_get_var(efi_handle_t handle, struct efi_loaded_image_64 *image, efi_char16_t *var)
{
	efi_status_t status = EFI_SUCCESS;
	void *val = NULL;
	uint64_t val_size = 100;
	efi_guid_t efi_var_guid = EFI_VAR_GUID;

	while (efi_grow_buffer(&status, &val, val_size + sizeof(efi_char16_t)))
		status = efi_rs_call(get_variable, var, &efi_var_guid, NULL, &val_size, val);

	if (val)
		((efi_char16_t *)val)[val_size / sizeof(efi_char16_t)] = L'\0';

	return val;
}

static void *efi_get_fdt(efi_handle_t handle, struct efi_loaded_image_64 *image)
{
	efi_char16_t var[] = ENV_VARNAME_DTBFILE;
	efi_char16_t *val;
	void *fdt = NULL;
	int fdtsize = 0;

	val = efi_get_var(handle, image, var);
	if (val) {
		efi_load_image(handle, image, &fdt, &fdtsize, val);
		if (fdtsize == 0)
			return NULL;
	} else if (efi_get_system_config_table(DEVICE_TREE_GUID, &fdt) != EFI_SUCCESS) {
		return NULL;
	}

	return fdt_check_header(fdt) == 0 ? fdt : NULL;
}
#else
static void *efi_get_fdt(efi_handle_t handle, struct efi_loaded_image_64 *image)
{
	return NULL;
}
#endif

static const struct {
	struct efi_vendor_dev_path	vendor;
	struct efi_generic_dev_path	end;
} __packed initrd_dev_path = {
	{
		{
			EFI_DEV_MEDIA,
			EFI_DEV_MEDIA_VENDOR,
			sizeof(struct efi_vendor_dev_path),
		},
		LINUX_EFI_INITRD_MEDIA_GUID
	}, {
		EFI_DEV_END_PATH,
		EFI_DEV_END_ENTIRE,
		sizeof(struct efi_generic_dev_path)
	}
};

static void efi_load_initrd(void)
{
	efi_guid_t lf2_proto_guid = EFI_LOAD_FILE2_PROTOCOL_GUID;
	efi_device_path_protocol_t *dp;
	efi_load_file2_protocol_t *lf2;
	efi_handle_t handle;
	efi_status_t status;
	unsigned long file_size = 0;

	initrd = NULL;
	initrd_size = 0;

	dp = (efi_device_path_protocol_t *)&initrd_dev_path;
	status = efi_bs_call(locate_device_path, &lf2_proto_guid, &dp, &handle);
	if (status != EFI_SUCCESS)
		return;

	status = efi_bs_call(handle_protocol, handle, &lf2_proto_guid, (void **)&lf2);
	assert(status == EFI_SUCCESS);

	status = efi_call_proto(lf2, load_file, dp, false, &file_size, NULL);
	assert(status == EFI_BUFFER_TOO_SMALL);

	status = efi_bs_call(allocate_pool, EFI_LOADER_DATA, file_size, (void **)&initrd);
	assert(status == EFI_SUCCESS);

	status = efi_call_proto(lf2, load_file, dp, false, &file_size, (void *)initrd);
	assert(status == EFI_SUCCESS);

	initrd_size = (u32)file_size;

	/*
	 * UEFI appends initrd=initrd to the command line when an initrd is present.
	 * Remove it in order to avoid confusing unit tests.
	 */
	if (!strcmp(__argv[__argc - 1], "initrd=initrd")) {
		__argv[__argc - 1] = NULL;
		__argc -= 1;
	}
}

efi_status_t efi_main(efi_handle_t handle, efi_system_table_t *sys_tab)
{
	int ret;
	efi_status_t status;
	efi_bootinfo_t efi_bootinfo;

	efi_system_table = sys_tab;

	/* Memory map struct values */
	efi_memory_desc_t *map = NULL;
	unsigned long map_size = 0, desc_size = 0, key = 0, buff_size = 0;
	u32 desc_ver;

	/* Helper variables needed to get the cmdline */
	struct efi_loaded_image_64 *image;
	efi_guid_t loaded_image_proto = LOADED_IMAGE_PROTOCOL_GUID;
	char *cmdline_ptr = NULL;
	int cmdline_size = 0;

	/*
	 * Get a handle to the loaded image protocol.  This is used to get
	 * information about the running image, such as size and the command
	 * line.
	 */
	status = efi_bs_call(handle_protocol, handle, &loaded_image_proto, (void *)&image);
	if (status != EFI_SUCCESS) {
		printf("Failed to get loaded image protocol\n");
		goto efi_main_error;
	}

	cmdline_ptr = efi_convert_cmdline(image, &cmdline_size);
	if (!cmdline_ptr) {
		printf("getting command line via LOADED_IMAGE_PROTOCOL\n");
		status = EFI_OUT_OF_RESOURCES;
		goto efi_main_error;
	}
	setup_args(cmdline_ptr);

	efi_load_initrd();

	efi_bootinfo.fdt = efi_get_fdt(handle, image);
	/* Set up efi_bootinfo */
	efi_bootinfo.mem_map.map = &map;
	efi_bootinfo.mem_map.map_size = &map_size;
	efi_bootinfo.mem_map.desc_size = &desc_size;
	efi_bootinfo.mem_map.desc_ver = &desc_ver;
	efi_bootinfo.mem_map.key_ptr = &key;
	efi_bootinfo.mem_map.buff_size = &buff_size;

	/* Get EFI memory map */
	status = efi_get_memory_map(&efi_bootinfo.mem_map);
	if (status != EFI_SUCCESS) {
		printf("Failed to get memory map\n");
		goto efi_main_error;
	}

#ifdef __riscv
	status = efi_get_boot_hartid();
	if (status != EFI_SUCCESS) {
		printf("Failed to get boot haritd\n");
		goto efi_main_error;
	}
#endif

	/* 
	 * Exit EFI boot services, let kvm-unit-tests take full control of the
	 * guest
	 */
	status = efi_exit_boot_services(handle, &efi_bootinfo.mem_map);
	if (status != EFI_SUCCESS) {
		printf("Failed to exit boot services\n");
		goto efi_main_error;
	}

	/* Set up arch-specific resources */
	status = setup_efi(&efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("Failed to set up arch-specific resources\n");
		goto efi_main_error;
	}

	printf("Address of image is: 0x%lx\n", (unsigned long)&_text);

	/* Run the test case */
	ret = main(__argc, __argv, __environ);

	/* Shutdown the guest VM */
	efi_exit(ret);

	/* Unreachable */
	return EFI_UNSUPPORTED;

efi_main_error:
	/* Shutdown the guest with error EFI status */
	efi_exit(status);

	/* Unreachable */
	return EFI_UNSUPPORTED;
}
