/*
 * All ITS* defines are lifted from include/linux/irqchip/arm-gic-v3.h
 *
 * Copyright (C) 2020, Red Hat Inc, Eric Auger <eric.auger@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#ifndef _ASMARM64_GIC_V3_ITS_H_
#define _ASMARM64_GIC_V3_ITS_H_

#ifndef _ASMARM_GIC_H_
#error Do not directly include <asm/gic-v3-its.h>. Include <asm/gic.h>
#endif

struct its_typer {
	unsigned int ite_size;
	unsigned int eventid_bits;
	unsigned int deviceid_bits;
	unsigned int collid_bits;
	bool pta;
	bool phys_lpi;
	bool virt_lpi;
};

struct its_baser {
	int index;
	size_t psz;
	int esz;
	bool indirect;
	void *table_addr;
};

#define GITS_BASER_NR_REGS		8
#define GITS_MAX_DEVICES		8
#define GITS_MAX_COLLECTIONS		8

struct its_device {
	u32 device_id;	/* device ID */
	u32 nr_ites;	/* Max Interrupt Translation Entries */
	void *itt;	/* Interrupt Translation Table GVA */
};

struct its_collection {
	u64 target_address;
	u16 col_id;
};

struct its_data {
	void *base;
	struct its_typer typer;
	struct its_baser device_baser;
	struct its_baser coll_baser;
	struct its_cmd_block *cmd_base;
	struct its_cmd_block *cmd_write;
	struct its_device devices[GITS_MAX_DEVICES];
	u32 nr_devices;		/* Allocated Devices */
	struct its_collection collections[GITS_MAX_COLLECTIONS];
	u16 nr_collections;	/* Allocated Collections */
};

extern struct its_data its_data;

#define gicv3_its_base()		(its_data.base)

#define GITS_CTLR			0x0000
#define GITS_IIDR			0x0004
#define GITS_TYPER			0x0008
#define GITS_CBASER			0x0080
#define GITS_CWRITER			0x0088
#define GITS_CREADR			0x0090
#define GITS_BASER			0x0100

#define GITS_TYPER_PLPIS		BIT(0)
#define GITS_TYPER_VLPIS		BIT(1)
#define GITS_TYPER_ITT_ENTRY_SIZE	GENMASK_ULL(7, 4)
#define GITS_TYPER_ITT_ENTRY_SIZE_SHIFT	4
#define GITS_TYPER_IDBITS		GENMASK_ULL(12, 8)
#define GITS_TYPER_IDBITS_SHIFT		8
#define GITS_TYPER_DEVBITS		GENMASK_ULL(17, 13)
#define GITS_TYPER_DEVBITS_SHIFT	13
#define GITS_TYPER_PTA			BIT(19)
#define GITS_TYPER_CIDBITS		GENMASK_ULL(35, 32)
#define GITS_TYPER_CIDBITS_SHIFT	32
#define GITS_TYPER_CIL			BIT(36)

#define GITS_CTLR_ENABLE		(1U << 0)

#define GITS_CBASER_VALID		(1UL << 63)

#define GITS_BASER_VALID		BIT(63)
#define GITS_BASER_INDIRECT		BIT(62)
#define GITS_BASER_TYPE_SHIFT		(56)
#define GITS_BASER_TYPE(r)		(((r) >> GITS_BASER_TYPE_SHIFT) & 7)
#define GITS_BASER_ENTRY_SIZE_SHIFT	(48)
#define GITS_BASER_ENTRY_SIZE(r)	((((r) >> GITS_BASER_ENTRY_SIZE_SHIFT) & 0x1f) + 1)
#define GITS_BASER_PAGE_SIZE_SHIFT	(8)
#define GITS_BASER_PAGE_SIZE_4K		(0UL << GITS_BASER_PAGE_SIZE_SHIFT)
#define GITS_BASER_PAGE_SIZE_16K	(1UL << GITS_BASER_PAGE_SIZE_SHIFT)
#define GITS_BASER_PAGE_SIZE_64K	(2UL << GITS_BASER_PAGE_SIZE_SHIFT)
#define GITS_BASER_PAGE_SIZE_MASK	(3UL << GITS_BASER_PAGE_SIZE_SHIFT)
#define GITS_BASER_PAGES_MAX		256
#define GITS_BASER_PAGES_SHIFT		(0)
#define GITS_BASER_NR_PAGES(r)		(((r) & 0xff) + 1)
#define GITS_BASER_PHYS_ADDR_MASK	0xFFFFFFFFF000
#define GITS_BASER_TYPE_NONE		0
#define GITS_BASER_TYPE_DEVICE		1
#define GITS_BASER_TYPE_COLLECTION	4

extern void its_parse_typer(void);
extern void its_init(void);
extern int its_baser_lookup(int i, struct its_baser *baser);
extern void its_enable_defaults(void);
extern struct its_device *its_create_device(u32 dev_id, int nr_ites);
extern struct its_collection *its_create_collection(u16 col_id, u32 target_pe);

#endif /* _ASMARM64_GIC_V3_ITS_H_ */
