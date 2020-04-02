/*
 * Copyright (C) 2020, Red Hat Inc, Eric Auger <eric.auger@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/gic.h>
#include <alloc_page.h>

void its_parse_typer(void)
{
	u64 typer = readq(gicv3_its_base() + GITS_TYPER);
	struct its_typer *t = &its_data.typer;

	t->ite_size = ((typer & GITS_TYPER_ITT_ENTRY_SIZE) >> GITS_TYPER_ITT_ENTRY_SIZE_SHIFT) + 1;
	t->pta = typer & GITS_TYPER_PTA;
	t->eventid_bits = ((typer & GITS_TYPER_IDBITS) >> GITS_TYPER_IDBITS_SHIFT) + 1;
	t->deviceid_bits = ((typer & GITS_TYPER_DEVBITS) >> GITS_TYPER_DEVBITS_SHIFT) + 1;

	if (typer & GITS_TYPER_CIL)
		t->collid_bits = ((typer & GITS_TYPER_CIDBITS) >> GITS_TYPER_CIDBITS_SHIFT) + 1;
	else
		t->collid_bits = 16;

	t->virt_lpi = typer & GITS_TYPER_VLPIS;
	t->phys_lpi = typer & GITS_TYPER_PLPIS;
}

int its_baser_lookup(int type, struct its_baser *baser)
{
	int i;

	for (i = 0; i < GITS_BASER_NR_REGS; i++) {
		void *reg_addr = gicv3_its_base() + GITS_BASER + i * 8;
		u64 val = readq(reg_addr);

		if (GITS_BASER_TYPE(val) == type) {
			assert((val & GITS_BASER_PAGE_SIZE_MASK) == GITS_BASER_PAGE_SIZE_64K);
			baser->esz = GITS_BASER_ENTRY_SIZE(val);
			baser->indirect = val & GITS_BASER_INDIRECT;
			baser->index = i;
			return 0;
		}
	}
	return -1;
}

/*
 * Allocate the BASER table (a single page of size @baser->psz)
 * and set the BASER valid
 */
static void its_baser_alloc_table(struct its_baser *baser, size_t size)
{
	unsigned long order = get_order(size >> PAGE_SHIFT);
	void *reg_addr = gicv3_its_base() + GITS_BASER + baser->index * 8;
	u64 val = readq(reg_addr);

	baser->table_addr = alloc_pages(order);

	val |= virt_to_phys(baser->table_addr) | GITS_BASER_VALID;

	writeq(val, reg_addr);
}

/*
 * init_cmd_queue - Allocate the command queue and initialize
 * CBASER, CWRITER
 */
static void its_cmd_queue_init(void)
{
	unsigned long order = get_order(SZ_64K >> PAGE_SHIFT);
	u64 cbaser;

	its_data.cmd_base = alloc_pages(order);

	cbaser = virt_to_phys(its_data.cmd_base) | (SZ_64K / SZ_4K - 1) | GITS_CBASER_VALID;

	writeq(cbaser, its_data.base + GITS_CBASER);

	its_data.cmd_write = its_data.cmd_base;
	writeq(0, its_data.base + GITS_CWRITER);
}

void its_init(void)
{
	if (!its_data.base)
		return;

	its_parse_typer();

	assert(!its_baser_lookup(GITS_BASER_TYPE_DEVICE, &its_data.device_baser));
	assert(!its_baser_lookup(GITS_BASER_TYPE_COLLECTION, &its_data.coll_baser));

	its_baser_alloc_table(&its_data.device_baser, SZ_64K);
	its_baser_alloc_table(&its_data.coll_baser, SZ_64K);

	its_cmd_queue_init();
}

/* must be called after gicv3_enable_defaults */
void its_enable_defaults(void)
{
	int cpu;

	/* Allocate LPI config and pending tables */
	gicv3_lpi_alloc_tables();

	for_each_present_cpu(cpu)
		gicv3_lpi_rdist_enable(cpu);

	writel(GITS_CTLR_ENABLE, its_data.base + GITS_CTLR);
}

struct its_device *its_create_device(u32 device_id, int nr_ites)
{
	struct its_device *new;
	unsigned long n;

	assert(its_data.nr_devices < GITS_MAX_DEVICES);

	new = &its_data.devices[its_data.nr_devices];

	new->device_id = device_id;
	new->nr_ites = nr_ites;

	n = (its_data.typer.ite_size * nr_ites) >> PAGE_SHIFT;
	new->itt = alloc_pages(get_order(n));

	its_data.nr_devices++;
	return new;
}

struct its_collection *its_create_collection(u16 col_id, u32 pe)
{
	struct its_collection *new;

	assert(its_data.nr_collections < GITS_MAX_COLLECTIONS);

	new = &its_data.collections[its_data.nr_collections];

	new->col_id = col_id;

	if (its_data.typer.pta)
		new->target_address = (u64)gicv3_data.redist_base[pe];
	else
		new->target_address = pe << 16;

	its_data.nr_collections++;
	return new;
}

struct its_device *its_get_device(u32 id)
{
	int i;

	for (i = 0; i < GITS_MAX_DEVICES; i++) {
		if (its_data.devices[i].device_id == id)
			return &its_data.devices[i];
	}
	assert(0);
}

struct its_collection *its_get_collection(u32 id)
{
	int i;

	for (i = 0; i < GITS_MAX_COLLECTIONS; i++) {
		if (its_data.collections[i].col_id == id)
			return &its_data.collections[i];
	}
	assert(0);
}
