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

