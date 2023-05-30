#ifndef _ACPI_H_
#define _ACPI_H_

#include "libcflat.h"

/*
 * All tables and structures must be byte-packed to match the ACPI
 * specification, since the tables are provided by the system firmware.
 */
#pragma pack(1)

#define ACPI_SIGNATURE(c1, c2, c3, c4) \
	((c1) | ((c2) << 8) | ((c3) << 16) | ((c4) << 24))

#define RSDP_SIGNATURE ACPI_SIGNATURE('R','S','D','P')
#define RSDT_SIGNATURE ACPI_SIGNATURE('R','S','D','T')
#define XSDT_SIGNATURE ACPI_SIGNATURE('X','S','D','T')
#define FACP_SIGNATURE ACPI_SIGNATURE('F','A','C','P')
#define FACS_SIGNATURE ACPI_SIGNATURE('F','A','C','S')
#define MADT_SIGNATURE ACPI_SIGNATURE('A','P','I','C')
#define SPCR_SIGNATURE ACPI_SIGNATURE('S','P','C','R')
#define GTDT_SIGNATURE ACPI_SIGNATURE('G','T','D','T')

#define ACPI_SIGNATURE_8BYTE(c1, c2, c3, c4, c5, c6, c7, c8) \
	(((uint64_t)(ACPI_SIGNATURE(c1, c2, c3, c4))) |	     \
	 ((uint64_t)(ACPI_SIGNATURE(c5, c6, c7, c8)) << 32))

#define RSDP_SIGNATURE_8BYTE (ACPI_SIGNATURE_8BYTE('R', 'S', 'D', ' ', 'P', 'T', 'R', ' '))

struct acpi_table_rsdp {	/* Root System Descriptor Pointer */
	u64 signature;		/* ACPI signature, contains "RSD PTR " */
	u8 checksum;		/* To make sum of struct == 0 */
	u8 oem_id[6];		/* OEM identification */
	u8 revision;		/* Must be 0 for 1.0, 2 for 2.0 */
	u32 rsdt_physical_address;	/* 32-bit physical address of RSDT */
	u32 length;		/* XSDT Length in bytes including hdr */
	u64 xsdt_physical_address;	/* 64-bit physical address of XSDT */
	u8 extended_checksum;	/* Checksum of entire table */
	u8 reserved[3];		/* Reserved field must be 0 */
};

#define ACPI_TABLE_HEADER_DEF		/* ACPI common table header */			\
	u32 signature;			/* ACPI signature (4 ASCII characters) */	\
	u32 length;			/* Length of table, in bytes, including header */ \
	u8  revision;			/* ACPI Specification minor version # */	\
	u8  checksum;			/* To make sum of entire table == 0 */		\
	u8  oem_id[6];			/* OEM identification */			\
	u8  oem_table_id[8];		/* OEM table identification */			\
	u32 oem_revision;		/* OEM revision number */			\
	u8  asl_compiler_id[4];		/* ASL compiler vendor ID */			\
	u32 asl_compiler_revision;	/* ASL compiler revision number */

struct acpi_table {
	ACPI_TABLE_HEADER_DEF
	char data[];
};

struct acpi_table_rsdt_rev1 {
	ACPI_TABLE_HEADER_DEF
	u32 table_offset_entry[];
};

struct acpi_table_xsdt {
	ACPI_TABLE_HEADER_DEF
	u64 table_offset_entry[];
};

struct acpi_generic_address {
	u8 space_id;		/* Address space where struct or register exists */
	u8 bit_width;		/* Size in bits of given register */
	u8 bit_offset;		/* Bit offset within the register */
	u8 access_width;	/* Minimum Access size (ACPI 3.0) */
	u64 address;		/* 64-bit address of struct or register */
};

struct acpi_table_fadt {
	ACPI_TABLE_HEADER_DEF	/* ACPI common table header */
	u32 firmware_ctrl;	/* Physical address of FACS */
	u32 dsdt;		/* Physical address of DSDT */
	u8 model;		/* System Interrupt Model */
	u8 reserved1;		/* Reserved */
	u16 sci_int;		/* System vector of SCI interrupt */
	u32 smi_cmd;		/* Port address of SMI command port */
	u8 acpi_enable;		/* Value to write to smi_cmd to enable ACPI */
	u8 acpi_disable;	/* Value to write to smi_cmd to disable ACPI */
	u8 S4bios_req;		/* Value to write to SMI CMD to enter S4BIOS state */
	u8 reserved2;		/* Reserved - must be zero */
	u32 pm1a_evt_blk;	/* Port address of Power Mgt 1a acpi_event Reg Blk */
	u32 pm1b_evt_blk;	/* Port address of Power Mgt 1b acpi_event Reg Blk */
	u32 pm1a_cnt_blk;	/* Port address of Power Mgt 1a Control Reg Blk */
	u32 pm1b_cnt_blk;	/* Port address of Power Mgt 1b Control Reg Blk */
	u32 pm2_cnt_blk;	/* Port address of Power Mgt 2 Control Reg Blk */
	u32 pm_tmr_blk;		/* Port address of Power Mgt Timer Ctrl Reg Blk */
	u32 gpe0_blk;		/* Port addr of General Purpose acpi_event 0 Reg Blk */
	u32 gpe1_blk;		/* Port addr of General Purpose acpi_event 1 Reg Blk */
	u8 pm1_evt_len;		/* Byte length of ports at pm1_x_evt_blk */
	u8 pm1_cnt_len;		/* Byte length of ports at pm1_x_cnt_blk */
	u8 pm2_cnt_len;		/* Byte Length of ports at pm2_cnt_blk */
	u8 pm_tmr_len;		/* Byte Length of ports at pm_tm_blk */
	u8 gpe0_blk_len;	/* Byte Length of ports at gpe0_blk */
	u8 gpe1_blk_len;	/* Byte Length of ports at gpe1_blk */
	u8 gpe1_base;		/* Offset in gpe model where gpe1 events start */
	u8 reserved3;		/* Reserved */
	u16 plvl2_lat;		/* Worst case HW latency to enter/exit C2 state */
	u16 plvl3_lat;		/* Worst case HW latency to enter/exit C3 state */
	u16 flush_size;		/* Size of area read to flush caches */
	u16 flush_stride;	/* Stride used in flushing caches */
	u8 duty_offset;		/* Bit location of duty cycle field in p_cnt reg */
	u8 duty_width;		/* Bit width of duty cycle field in p_cnt reg */
	u8 day_alrm;		/* Index to day-of-month alarm in RTC CMOS RAM */
	u8 mon_alrm;		/* Index to month-of-year alarm in RTC CMOS RAM */
	u8 century;		/* Index to century in RTC CMOS RAM */
	u16 boot_flags;		/* IA-PC Boot Architecture Flags (see below for individual flags) */
	u8 reserved;		/* Reserved, must be zero */
	u32 flags;		/* Miscellaneous flag bits (see below for individual flags) */
	struct acpi_generic_address reset_register;	/* 64-bit address of the Reset register */
	u8 reset_value;		/* Value to write to the reset_register port to reset the system */
	u16 arm_boot_flags;	/* ARM-Specific Boot Flags (see below for individual flags) (ACPI 5.1) */
	u8 minor_revision;	/* FADT Minor Revision (ACPI 5.1) */
	u64 Xfacs;		/* 64-bit physical address of FACS */
	u64 Xdsdt;		/* 64-bit physical address of DSDT */
	struct acpi_generic_address xpm1a_event_block;	/* 64-bit Extended Power Mgt 1a Event Reg Blk address */
	struct acpi_generic_address xpm1b_event_block;	/* 64-bit Extended Power Mgt 1b Event Reg Blk address */
	struct acpi_generic_address xpm1a_control_block;	/* 64-bit Extended Power Mgt 1a Control Reg Blk address */
	struct acpi_generic_address xpm1b_control_block;	/* 64-bit Extended Power Mgt 1b Control Reg Blk address */
	struct acpi_generic_address xpm2_control_block;	/* 64-bit Extended Power Mgt 2 Control Reg Blk address */
	struct acpi_generic_address xpm_timer_block;	/* 64-bit Extended Power Mgt Timer Ctrl Reg Blk address */
	struct acpi_generic_address xgpe0_block;	/* 64-bit Extended General Purpose Event 0 Reg Blk address */
	struct acpi_generic_address xgpe1_block;	/* 64-bit Extended General Purpose Event 1 Reg Blk address */
	struct acpi_generic_address sleep_control;	/* 64-bit Sleep Control register (ACPI 5.0) */
	struct acpi_generic_address sleep_status;	/* 64-bit Sleep Status register (ACPI 5.0) */
	u64 hypervisor_id;	/* Hypervisor Vendor ID (ACPI 6.0) */
};

/* Masks for FADT ARM Boot Architecture Flags (arm_boot_flags) ACPI 5.1 */

#define ACPI_FADT_PSCI_COMPLIANT    (1)	/* 00: [V5+] PSCI 0.2+ is implemented */
#define ACPI_FADT_PSCI_USE_HVC      (1<<1)	/* 01: [V5+] HVC must be used instead of SMC as the PSCI conduit */

struct acpi_table_facs_rev1 {
	u32 signature;		/* ACPI Signature */
	u32 length;		/* Length of structure, in bytes */
	u32 hardware_signature;	/* Hardware configuration signature */
	u32 firmware_waking_vector;	/* ACPI OS waking vector */
	u32 global_lock;	/* Global Lock */
	u32 S4bios_f:1;		/* Indicates if S4BIOS support is present */
	u32 reserved1:31;	/* Must be 0 */
	u8 reserved3[40];	/* Reserved - must be zero */
};

struct acpi_table_madt {
	ACPI_TABLE_HEADER_DEF	/* ACPI common table header */
	u32 address;		/* Physical address of local APIC */
	u32 flags;
};

struct acpi_subtable_header {
	u8 type;
	u8 length;
};

typedef int (*acpi_table_handler)(struct acpi_subtable_header *header);

/* 11: Generic interrupt - GICC (ACPI 5.0 + ACPI 6.0 + ACPI 6.3 changes) */

struct acpi_madt_generic_interrupt {
	u8 type;
	u8 length;
	u16 reserved;		/* reserved - must be zero */
	u32 cpu_interface_number;
	u32 uid;
	u32 flags;
	u32 parking_version;
	u32 performance_interrupt;
	u64 parked_address;
	u64 base_address;
	u64 gicv_base_address;
	u64 gich_base_address;
	u32 vgic_interrupt;
	u64 gicr_base_address;
	u64 arm_mpidr;
	u8 efficiency_class;
	u8 reserved2[1];
	u16 spe_interrupt;	/* ACPI 6.3 */
};

/* 12: Generic Distributor (ACPI 5.0 + ACPI 6.0 changes) */

struct acpi_madt_generic_distributor {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 gic_id;
	u64 base_address;
	u32 global_irq_base;
	u8 version;
	u8 reserved2[3];	/* reserved - must be zero */
};

/* Values for Version field above */

enum acpi_madt_gic_version {
	ACPI_MADT_GIC_VERSION_NONE = 0,
	ACPI_MADT_GIC_VERSION_V1 = 1,
	ACPI_MADT_GIC_VERSION_V2 = 2,
	ACPI_MADT_GIC_VERSION_V3 = 3,
	ACPI_MADT_GIC_VERSION_V4 = 4,
	ACPI_MADT_GIC_VERSION_RESERVED = 5	/* 5 and greater are reserved */
};

/* 14: Generic Redistributor (ACPI 5.1) */

struct acpi_madt_generic_redistributor {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u64 base_address;
	u32 length;
};

/* 15: Generic Translator (ACPI 6.0) */

struct acpi_madt_generic_translator {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 translation_id;
	u64 base_address;
	u32 reserved2;
};

/* Values for MADT subtable type in struct acpi_subtable_header */

enum acpi_madt_type {
	ACPI_MADT_TYPE_LOCAL_APIC = 0,
	ACPI_MADT_TYPE_IO_APIC = 1,
	ACPI_MADT_TYPE_INTERRUPT_OVERRIDE = 2,
	ACPI_MADT_TYPE_NMI_SOURCE = 3,
	ACPI_MADT_TYPE_LOCAL_APIC_NMI = 4,
	ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE = 5,
	ACPI_MADT_TYPE_IO_SAPIC = 6,
	ACPI_MADT_TYPE_LOCAL_SAPIC = 7,
	ACPI_MADT_TYPE_INTERRUPT_SOURCE = 8,
	ACPI_MADT_TYPE_LOCAL_X2APIC = 9,
	ACPI_MADT_TYPE_LOCAL_X2APIC_NMI = 10,
	ACPI_MADT_TYPE_GENERIC_INTERRUPT = 11,
	ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR = 12,
	ACPI_MADT_TYPE_GENERIC_MSI_FRAME = 13,
	ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR = 14,
	ACPI_MADT_TYPE_GENERIC_TRANSLATOR = 15,
	ACPI_MADT_TYPE_RESERVED = 16	/* 16 and greater are reserved */
};

/* MADT Local APIC flags */
#define ACPI_MADT_ENABLED		(1)	/* 00: Processor is usable if set */

struct spcr_descriptor {
	ACPI_TABLE_HEADER_DEF	/* ACPI common table header */
	u8 interface_type;	/* 0=full 16550, 1=subset of 16550 */
	u8 reserved[3];
	struct acpi_generic_address serial_port;
	u8 interrupt_type;
	u8 pc_interrupt;
	u32 interrupt;
	u8 baud_rate;
	u8 parity;
	u8 stop_bits;
	u8 flow_control;
	u8 terminal_type;
	u8 reserved1;
	u16 pci_device_id;
	u16 pci_vendor_id;
	u8 pci_bus;
	u8 pci_device;
	u8 pci_function;
	u32 pci_flags;
	u8 pci_segment;
	u32 reserved2;
};

struct acpi_table_gtdt {
	ACPI_TABLE_HEADER_DEF	/* ACPI common table header */
	u64 counter_block_addresss;
	u32 reserved;
	u32 secure_el1_interrupt;
	u32 secure_el1_flags;
	u32 non_secure_el1_interrupt;
	u32 non_secure_el1_flags;
	u32 virtual_timer_interrupt;
	u32 virtual_timer_flags;
	u32 non_secure_el2_interrupt;
	u32 non_secure_el2_flags;
	u64 counter_read_block_address;
	u32 platform_timer_count;
	u32 platform_timer_offset;
};

/* Reset to default packing */
#pragma pack()

void set_efi_rsdp(struct acpi_table_rsdp *rsdp);
void *find_acpi_table_addr(u32 sig);
int acpi_table_parse_madt(enum acpi_madt_type mtype, acpi_table_handler handler);

#endif
