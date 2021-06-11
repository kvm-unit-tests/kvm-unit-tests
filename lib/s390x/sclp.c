/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x SCLP driver
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 */

#include <libcflat.h>
#include <asm/page.h>
#include <asm/arch_def.h>
#include <asm/interrupt.h>
#include <asm/barrier.h>
#include <asm/spinlock.h>
#include "sclp.h"
#include <alloc_phys.h>
#include <alloc_page.h>

extern unsigned long stacktop;

static uint64_t storage_increment_size;
static uint64_t max_ram_size;
static uint64_t ram_size;
char _read_info[PAGE_SIZE] __attribute__((__aligned__(PAGE_SIZE)));
static ReadInfo *read_info;
struct sclp_facilities sclp_facilities;

char _sccb[PAGE_SIZE] __attribute__((__aligned__(4096)));
static volatile bool sclp_busy;
static struct spinlock sclp_lock;

static void mem_init(phys_addr_t mem_end)
{
	phys_addr_t freemem_start = (phys_addr_t)&stacktop;
	phys_addr_t base, top;

	phys_alloc_init(freemem_start, mem_end - freemem_start);
	phys_alloc_get_unused(&base, &top);
	base = PAGE_ALIGN(base) >> PAGE_SHIFT;
	top = top >> PAGE_SHIFT;

	/* Make the pages available to the physical allocator */
	page_alloc_init_area(AREA_ANY_NUMBER, base, top);
	page_alloc_ops_enable();
}

void sclp_setup_int(void)
{
	uint64_t mask;

	ctl_set_bit(0, CTL0_SERVICE_SIGNAL);

	mask = extract_psw_mask();
	mask |= PSW_MASK_EXT;
	load_psw_mask(mask);
}

void sclp_handle_ext(void)
{
	ctl_clear_bit(0, CTL0_SERVICE_SIGNAL);
	spin_lock(&sclp_lock);
	sclp_busy = false;
	spin_unlock(&sclp_lock);
}

void sclp_wait_busy(void)
{
	while (sclp_busy)
		mb();
}

void sclp_mark_busy(void)
{
	/*
	 * With multiple CPUs we might need to wait for another CPU's
	 * request before grabbing the busy indication.
	 */
	while (true) {
		sclp_wait_busy();
		spin_lock(&sclp_lock);
		if (!sclp_busy) {
			sclp_busy = true;
			spin_unlock(&sclp_lock);
			return;
		}
		spin_unlock(&sclp_lock);
	}
}

static void sclp_read_scp_info(ReadInfo *ri, int length)
{
	unsigned int commands[] = { SCLP_CMDW_READ_SCP_INFO_FORCED,
				    SCLP_CMDW_READ_SCP_INFO };
	int i, cc;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		sclp_mark_busy();
		memset(&ri->h, 0, sizeof(ri->h));
		ri->h.length = length;

		cc = sclp_service_call(commands[i], ri);
		if (cc)
			break;
		if (ri->h.response_code == SCLP_RC_NORMAL_READ_COMPLETION)
			return;
		if (ri->h.response_code != SCLP_RC_INVALID_SCLP_COMMAND)
			break;
	}
	report_abort("READ_SCP_INFO failed");
}

void sclp_read_info(void)
{
	sclp_read_scp_info((void *)_read_info, SCCB_SIZE);
	read_info = (ReadInfo *)_read_info;
}

int sclp_get_cpu_num(void)
{
	assert(read_info);
	return read_info->entries_cpu;
}

CPUEntry *sclp_get_cpu_entries(void)
{
	assert(read_info);
	return (CPUEntry *)(_read_info + read_info->offset_cpu);
}

static bool sclp_feat_check(int byte, int bit)
{
	uint8_t *rib = (uint8_t *)read_info;

	return !!(rib[byte] & (0x80 >> bit));
}

void sclp_facilities_setup(void)
{
	unsigned short cpu0_addr = stap();
	CPUEntry *cpu;
	int i;

	assert(read_info);

	cpu = sclp_get_cpu_entries();
	if (read_info->offset_cpu > 134)
		sclp_facilities.has_diag318 = read_info->byte_134_diag318;
	sclp_facilities.has_gsls = sclp_feat_check(85, SCLP_FEAT_85_BIT_GSLS);
	sclp_facilities.has_kss = sclp_feat_check(98, SCLP_FEAT_98_BIT_KSS);
	sclp_facilities.has_cmma = sclp_feat_check(116, SCLP_FEAT_116_BIT_CMMA);
	sclp_facilities.has_64bscao = sclp_feat_check(116, SCLP_FEAT_116_BIT_64BSCAO);
	sclp_facilities.has_esca = sclp_feat_check(116, SCLP_FEAT_116_BIT_ESCA);
	sclp_facilities.has_ibs = sclp_feat_check(117, SCLP_FEAT_117_BIT_IBS);
	sclp_facilities.has_pfmfi = sclp_feat_check(117, SCLP_FEAT_117_BIT_PFMFI);

	for (i = 0; i < read_info->entries_cpu; i++, cpu++) {
		/*
		 * The logic for only reading the facilities from the
		 * boot cpu comes from the kernel. I haven't yet found
		 * documentation that explains why this is necessary
		 * but I figure there's a reason behind doing it this
		 * way.
		 */
		if (cpu->address == cpu0_addr) {
			sclp_facilities.has_sief2 = cpu->feat_sief2;
			sclp_facilities.has_skeyi = cpu->feat_skeyi;
			sclp_facilities.has_siif = cpu->feat_siif;
			sclp_facilities.has_sigpif = cpu->feat_sigpif;
			sclp_facilities.has_ib = cpu->feat_ib;
			sclp_facilities.has_cei = cpu->feat_cei;
			break;
		}
	}
}

/* Perform service call. Return 0 on success, non-zero otherwise. */
int sclp_service_call(unsigned int command, void *sccb)
{
	int cc;

	sclp_setup_int();
	cc = servc(command, __pa(sccb));
	sclp_wait_busy();
	if (cc == 3)
		return -1;
	if (cc == 2)
		return -1;
	return 0;
}

void sclp_memory_setup(void)
{
	uint64_t rnmax, rnsize;
	int cc;

	assert(read_info);

	/* calculate the storage increment size */
	rnsize = read_info->rnsize;
	if (!rnsize) {
		rnsize = read_info->rnsize2;
	}
	storage_increment_size = rnsize << 20;

	/* calculate the maximum memory size */
	rnmax = read_info->rnmax;
	if (!rnmax) {
		rnmax = read_info->rnmax2;
	}
	max_ram_size = rnmax * storage_increment_size;

	/* lowcore is always accessible, so the first increment is accessible */
	ram_size = storage_increment_size;

	/* probe for r/w memory up to max memory size */
	while (ram_size < max_ram_size) {
		expect_pgm_int();
		cc = tprot(ram_size + storage_increment_size - 1);
		/* stop once we receive an exception or have protected memory */
		if (clear_pgm_int() || cc != 0)
			break;
		ram_size += storage_increment_size;
	}

	mem_init(ram_size);
}

uint64_t get_ram_size(void)
{
	return ram_size;
}

uint64_t get_max_ram_size(void)
{
	return max_ram_size;
}
