/* SPDX-License-Identifier: GPL-2.0 */
/* Relevant definitions from linux/efi.h. */

#ifndef __LINUX_UEFI_H
#define __LINUX_UEFI_H

#include "libcflat.h"

#ifndef __packed
# define __packed		__attribute__((__packed__))
#endif

#define BITS_PER_LONG 64

#define EFI_SUCCESS		0
#define EFI_LOAD_ERROR		( 1 | (1UL << (BITS_PER_LONG-1)))
#define EFI_INVALID_PARAMETER	( 2 | (1UL << (BITS_PER_LONG-1)))
#define EFI_UNSUPPORTED		( 3 | (1UL << (BITS_PER_LONG-1)))
#define EFI_BAD_BUFFER_SIZE	( 4 | (1UL << (BITS_PER_LONG-1)))
#define EFI_BUFFER_TOO_SMALL	( 5 | (1UL << (BITS_PER_LONG-1)))
#define EFI_NOT_READY		( 6 | (1UL << (BITS_PER_LONG-1)))
#define EFI_DEVICE_ERROR	( 7 | (1UL << (BITS_PER_LONG-1)))
#define EFI_WRITE_PROTECTED	( 8 | (1UL << (BITS_PER_LONG-1)))
#define EFI_OUT_OF_RESOURCES	( 9 | (1UL << (BITS_PER_LONG-1)))
#define EFI_NOT_FOUND		(14 | (1UL << (BITS_PER_LONG-1)))
#define EFI_TIMEOUT		(18 | (1UL << (BITS_PER_LONG-1)))
#define EFI_ABORTED		(21 | (1UL << (BITS_PER_LONG-1)))
#define EFI_SECURITY_VIOLATION	(26 | (1UL << (BITS_PER_LONG-1)))

typedef unsigned long efi_status_t;
typedef u8 efi_bool_t;
typedef u16 efi_char16_t;		/* UNICODE character */
typedef u64 efi_physical_addr_t;
typedef void *efi_handle_t;

#define __efiapi __attribute__((ms_abi))

/*
 * The UEFI spec and EDK2 reference implementation both define EFI_GUID as
 * struct { u32 a; u16; b; u16 c; u8 d[8]; }; and so the implied alignment
 * is 32 bits not 8 bits like our guid_t. In some cases (i.e., on 32-bit ARM),
 * this means that firmware services invoked by the kernel may assume that
 * efi_guid_t* arguments are 32-bit aligned, and use memory accessors that
 * do not tolerate misalignment. So let's set the minimum alignment to 32 bits.
 *
 * Note that the UEFI spec as well as some comments in the EDK2 code base
 * suggest that EFI_GUID should be 64-bit aligned, but this appears to be
 * a mistake, given that no code seems to exist that actually enforces that
 * or relies on it.
 */
typedef struct {
	u8 b[16];
} guid_t __attribute__((aligned(__alignof__(u32))));
typedef guid_t efi_guid_t;

#define EFI_GUID(a, b, c, d...) (efi_guid_t){ {					\
	(a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff,	\
	(b) & 0xff, ((b) >> 8) & 0xff,						\
	(c) & 0xff, ((c) >> 8) & 0xff, d } }

#define ACPI_TABLE_GUID EFI_GUID(0xeb9d2d30, 0x2d88, 0x11d3, 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)

#define LOADED_IMAGE_PROTOCOL_GUID EFI_GUID(0x5b1b31a1, 0x9562, 0x11d2,  0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

typedef struct {
	efi_guid_t guid;
	void *table;
} efi_config_table_t;

/*
 * Generic EFI table header
 */
typedef	struct {
	u64 signature;
	u32 revision;
	u32 headersize;
	u32 crc32;
	u32 reserved;
} efi_table_hdr_t;

/*
 * Memory map descriptor:
 */

/* Memory types: */
#define EFI_RESERVED_TYPE		 0
#define EFI_LOADER_CODE			 1
#define EFI_LOADER_DATA			 2
#define EFI_BOOT_SERVICES_CODE		 3
#define EFI_BOOT_SERVICES_DATA		 4
#define EFI_RUNTIME_SERVICES_CODE	 5
#define EFI_RUNTIME_SERVICES_DATA	 6
#define EFI_CONVENTIONAL_MEMORY		 7
#define EFI_UNUSABLE_MEMORY		 8
#define EFI_ACPI_RECLAIM_MEMORY		 9
#define EFI_ACPI_MEMORY_NVS		10
#define EFI_MEMORY_MAPPED_IO		11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE	12
#define EFI_PAL_CODE			13
#define EFI_PERSISTENT_MEMORY		14
#define EFI_MAX_MEMORY_TYPE		15

/* Attribute values: */
#define EFI_MEMORY_UC		((u64)0x0000000000000001ULL)	/* uncached */
#define EFI_MEMORY_WC		((u64)0x0000000000000002ULL)	/* write-coalescing */
#define EFI_MEMORY_WT		((u64)0x0000000000000004ULL)	/* write-through */
#define EFI_MEMORY_WB		((u64)0x0000000000000008ULL)	/* write-back */
#define EFI_MEMORY_UCE		((u64)0x0000000000000010ULL)	/* uncached, exported */
#define EFI_MEMORY_WP		((u64)0x0000000000001000ULL)	/* write-protect */
#define EFI_MEMORY_RP		((u64)0x0000000000002000ULL)	/* read-protect */
#define EFI_MEMORY_XP		((u64)0x0000000000004000ULL)	/* execute-protect */
#define EFI_MEMORY_NV		((u64)0x0000000000008000ULL)	/* non-volatile */
#define EFI_MEMORY_MORE_RELIABLE \
				((u64)0x0000000000010000ULL)	/* higher reliability */
#define EFI_MEMORY_RO		((u64)0x0000000000020000ULL)	/* read-only */
#define EFI_MEMORY_SP		((u64)0x0000000000040000ULL)	/* soft reserved */
#define EFI_MEMORY_CPU_CRYPTO	((u64)0x0000000000080000ULL)	/* supports encryption */
#define EFI_MEMORY_RUNTIME	((u64)0x8000000000000000ULL)	/* range requires runtime mapping */
#define EFI_MEMORY_DESCRIPTOR_VERSION	1

#define EFI_PAGE_SHIFT		12
#define EFI_PAGE_SIZE		(1UL << EFI_PAGE_SHIFT)
#define EFI_PAGES_MAX		(U64_MAX >> EFI_PAGE_SHIFT)

typedef struct {
	u32 type;
	u32 pad;
	u64 phys_addr;
	u64 virt_addr;
	u64 num_pages;
	u64 attribute;
} efi_memory_desc_t;

typedef struct {
	efi_guid_t guid;
	u32 headersize;
	u32 flags;
	u32 imagesize;
} efi_capsule_header_t;

/*
 * EFI capsule flags
 */
#define EFI_CAPSULE_PERSIST_ACROSS_RESET	0x00010000
#define EFI_CAPSULE_POPULATE_SYSTEM_TABLE	0x00020000
#define EFI_CAPSULE_INITIATE_RESET		0x00040000

struct capsule_info {
	efi_capsule_header_t	header;
	efi_capsule_header_t	*capsule;
	int			reset_type;
	long			index;
	size_t			count;
	size_t			total_size;
	struct page		**pages;
	phys_addr_t		*phys;
	size_t			page_bytes_remain;
};

int __efi_capsule_setup_info(struct capsule_info *cap_info);

/*
 * Types and defines for Time Services
 */
#define EFI_TIME_ADJUST_DAYLIGHT 0x1
#define EFI_TIME_IN_DAYLIGHT     0x2
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff

typedef struct {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 minute;
	u8 second;
	u8 pad1;
	u32 nanosecond;
	s16 timezone;
	u8 daylight;
	u8 pad2;
} efi_time_t;

typedef struct {
	u32 resolution;
	u32 accuracy;
	u8 sets_to_zero;
} efi_time_cap_t;

typedef void *efi_event_t;
/* Note that notifications won't work in mixed mode */
typedef void (__efiapi *efi_event_notify_t)(efi_event_t, void *);

typedef enum {
	EfiTimerCancel,
	EfiTimerPeriodic,
	EfiTimerRelative
} EFI_TIMER_DELAY;

/*
 * EFI Device Path information
 */
#define EFI_DEV_HW			0x01
#define  EFI_DEV_PCI				 1
#define  EFI_DEV_PCCARD				 2
#define  EFI_DEV_MEM_MAPPED			 3
#define  EFI_DEV_VENDOR				 4
#define  EFI_DEV_CONTROLLER			 5
#define EFI_DEV_ACPI			0x02
#define   EFI_DEV_BASIC_ACPI			 1
#define   EFI_DEV_EXPANDED_ACPI			 2
#define EFI_DEV_MSG			0x03
#define   EFI_DEV_MSG_ATAPI			 1
#define   EFI_DEV_MSG_SCSI			 2
#define   EFI_DEV_MSG_FC			 3
#define   EFI_DEV_MSG_1394			 4
#define   EFI_DEV_MSG_USB			 5
#define   EFI_DEV_MSG_USB_CLASS			15
#define   EFI_DEV_MSG_I20			 6
#define   EFI_DEV_MSG_MAC			11
#define   EFI_DEV_MSG_IPV4			12
#define   EFI_DEV_MSG_IPV6			13
#define   EFI_DEV_MSG_INFINIBAND		 9
#define   EFI_DEV_MSG_UART			14
#define   EFI_DEV_MSG_VENDOR			10
#define EFI_DEV_MEDIA			0x04
#define   EFI_DEV_MEDIA_HARD_DRIVE		 1
#define   EFI_DEV_MEDIA_CDROM			 2
#define   EFI_DEV_MEDIA_VENDOR			 3
#define   EFI_DEV_MEDIA_FILE			 4
#define   EFI_DEV_MEDIA_PROTOCOL		 5
#define EFI_DEV_BIOS_BOOT		0x05
#define EFI_DEV_END_PATH		0x7F
#define EFI_DEV_END_PATH2		0xFF
#define   EFI_DEV_END_INSTANCE			0x01
#define   EFI_DEV_END_ENTIRE			0xFF

struct efi_generic_dev_path {
	u8				type;
	u8				sub_type;
	u16				length;
} __packed;

typedef struct efi_generic_dev_path efi_device_path_protocol_t;

/*
 * EFI Boot Services table
 */
typedef struct {
	efi_table_hdr_t hdr;
	void *raise_tpl;
	void *restore_tpl;
	efi_status_t(__efiapi *allocate_pages)(int, int, unsigned long,
					       efi_physical_addr_t *);
	efi_status_t(__efiapi *free_pages)(efi_physical_addr_t,
					   unsigned long);
	efi_status_t(__efiapi *get_memory_map)(unsigned long *, void *,
					       unsigned long *,
					       unsigned long *, u32 *);
	efi_status_t(__efiapi *allocate_pool)(int, unsigned long,
					      void **);
	efi_status_t(__efiapi *free_pool)(void *);
	efi_status_t(__efiapi *create_event)(u32, unsigned long,
					     efi_event_notify_t, void *,
					     efi_event_t *);
	efi_status_t(__efiapi *set_timer)(efi_event_t,
					  EFI_TIMER_DELAY, u64);
	efi_status_t(__efiapi *wait_for_event)(unsigned long,
					       efi_event_t *,
					       unsigned long *);
	void *signal_event;
	efi_status_t(__efiapi *close_event)(efi_event_t);
	void *check_event;
	void *install_protocol_interface;
	void *reinstall_protocol_interface;
	void *uninstall_protocol_interface;
	efi_status_t(__efiapi *handle_protocol)(efi_handle_t,
						efi_guid_t *, void **);
	void *__reserved;
	void *register_protocol_notify;
	efi_status_t(__efiapi *locate_handle)(int, efi_guid_t *,
					      void *, unsigned long *,
					      efi_handle_t *);
	efi_status_t(__efiapi *locate_device_path)(efi_guid_t *,
						   efi_device_path_protocol_t **,
						   efi_handle_t *);
	efi_status_t(__efiapi *install_configuration_table)(efi_guid_t *,
							    void *);
	void *load_image;
	void *start_image;
	efi_status_t(__efiapi *exit)(efi_handle_t,
				     efi_status_t,
				     unsigned long,
				     efi_char16_t *);
	void *unload_image;
	efi_status_t(__efiapi *exit_boot_services)(efi_handle_t,
						   unsigned long);
	void *get_next_monotonic_count;
	efi_status_t(__efiapi *stall)(unsigned long);
	void *set_watchdog_timer;
	void *connect_controller;
	efi_status_t(__efiapi *disconnect_controller)(efi_handle_t,
						      efi_handle_t,
						      efi_handle_t);
	void *open_protocol;
	void *close_protocol;
	void *open_protocol_information;
	void *protocols_per_handle;
	void *locate_handle_buffer;
	efi_status_t(__efiapi *locate_protocol)(efi_guid_t *, void *,
						void **);
	void *install_multiple_protocol_interfaces;
	void *uninstall_multiple_protocol_interfaces;
	void *calculate_crc32;
	void *copy_mem;
	void *set_mem;
	void *create_event_ex;
} efi_boot_services_t;

/*
 * Types and defines for EFI ResetSystem
 */
#define EFI_RESET_COLD 0
#define EFI_RESET_WARM 1
#define EFI_RESET_SHUTDOWN 2

/*
 * EFI Runtime Services table
 */
#define EFI_RUNTIME_SERVICES_SIGNATURE ((u64)0x5652453544e5552ULL)
#define EFI_RUNTIME_SERVICES_REVISION  0x00010000

typedef efi_status_t efi_get_time_t (efi_time_t *tm, efi_time_cap_t *tc);
typedef efi_status_t efi_set_time_t (efi_time_t *tm);
typedef efi_status_t efi_get_wakeup_time_t (efi_bool_t *enabled, efi_bool_t *pending,
					    efi_time_t *tm);
typedef efi_status_t efi_set_wakeup_time_t (efi_bool_t enabled, efi_time_t *tm);
typedef efi_status_t efi_get_variable_t (efi_char16_t *name, efi_guid_t *vendor, u32 *attr,
					 unsigned long *data_size, void *data);
typedef efi_status_t efi_get_next_variable_t (unsigned long *name_size, efi_char16_t *name,
					      efi_guid_t *vendor);
typedef efi_status_t efi_set_variable_t (efi_char16_t *name, efi_guid_t *vendor,
					 u32 attr, unsigned long data_size,
					 void *data);
typedef efi_status_t efi_get_next_high_mono_count_t (u32 *count);
typedef void efi_reset_system_t (int reset_type, efi_status_t status,
				 unsigned long data_size, efi_char16_t *data);
typedef efi_status_t efi_set_virtual_address_map_t (unsigned long memory_map_size,
						unsigned long descriptor_size,
						u32 descriptor_version,
						efi_memory_desc_t *virtual_map);
typedef efi_status_t efi_query_variable_info_t(u32 attr,
					       u64 *storage_space,
					       u64 *remaining_space,
					       u64 *max_variable_size);
typedef efi_status_t efi_update_capsule_t(efi_capsule_header_t **capsules,
					  unsigned long count,
					  unsigned long sg_list);
typedef efi_status_t efi_query_capsule_caps_t(efi_capsule_header_t **capsules,
					      unsigned long count,
					      u64 *max_size,
					      int *reset_type);
typedef efi_status_t efi_query_variable_store_t(u32 attributes,
						unsigned long size,
						bool nonblocking);

typedef struct {
	efi_table_hdr_t				hdr;
	efi_get_time_t __efiapi			*get_time;
	efi_set_time_t __efiapi			*set_time;
	efi_get_wakeup_time_t __efiapi		*get_wakeup_time;
	efi_set_wakeup_time_t __efiapi		*set_wakeup_time;
	efi_set_virtual_address_map_t __efiapi	*set_virtual_address_map;
	void					*convert_pointer;
	efi_get_variable_t __efiapi		*get_variable;
	efi_get_next_variable_t __efiapi	*get_next_variable;
	efi_set_variable_t __efiapi		*set_variable;
	efi_get_next_high_mono_count_t __efiapi	*get_next_high_mono_count;
	efi_reset_system_t __efiapi		*reset_system;
	efi_update_capsule_t __efiapi		*update_capsule;
	efi_query_capsule_caps_t __efiapi	*query_capsule_caps;
	efi_query_variable_info_t __efiapi	*query_variable_info;
} efi_runtime_services_t;

#define EFI_SYSTEM_TABLE_SIGNATURE ((u64)0x5453595320494249ULL)

#define EFI_2_30_SYSTEM_TABLE_REVISION  ((2 << 16) | (30))
#define EFI_2_20_SYSTEM_TABLE_REVISION  ((2 << 16) | (20))
#define EFI_2_10_SYSTEM_TABLE_REVISION  ((2 << 16) | (10))
#define EFI_2_00_SYSTEM_TABLE_REVISION  ((2 << 16) | (00))
#define EFI_1_10_SYSTEM_TABLE_REVISION  ((1 << 16) | (10))
#define EFI_1_02_SYSTEM_TABLE_REVISION  ((1 << 16) | (02))

typedef union efi_simple_text_input_protocol efi_simple_text_input_protocol_t;
typedef union efi_simple_text_output_protocol efi_simple_text_output_protocol_t;

typedef struct {
	efi_table_hdr_t hdr;
	unsigned long fw_vendor;	/* physical addr of CHAR16 vendor string */
	u32 fw_revision;
	unsigned long con_in_handle;
	efi_simple_text_input_protocol_t *con_in;
	unsigned long con_out_handle;
	efi_simple_text_output_protocol_t *con_out;
	unsigned long stderr_handle;
	unsigned long stderr;
	efi_runtime_services_t *runtime;
	efi_boot_services_t *boottime;
	unsigned long nr_tables;
	unsigned long tables;
} efi_system_table_t;

struct efi_boot_memmap {
	efi_memory_desc_t       **map;
	unsigned long           *map_size;
	unsigned long           *desc_size;
	u32                     *desc_ver;
	unsigned long           *key_ptr;
	unsigned long           *buff_size;
};

#define __aligned_u64 u64 __attribute__((aligned(8)))

struct efi_loaded_image_64 {
	u32			revision;
	efi_handle_t		parent_handle;
	efi_system_table_t	*system_table;
	efi_handle_t		device_handle;
	void			*file_path;
	void			*reserved;
	u32			load_options_size;
	void			*load_options;
	void			*image_base;
	__aligned_u64		image_size;
	unsigned int		image_code_type;
	unsigned int		image_data_type;
	efi_status_t		(__efiapi * unload)(efi_handle_t image_handle);
};

#define efi_bs_call(func, ...) efi_system_table->boottime->func(__VA_ARGS__)
#define efi_rs_call(func, ...) efi_system_table->runtime->func(__VA_ARGS__)

#endif /* __LINUX_UEFI_H */
