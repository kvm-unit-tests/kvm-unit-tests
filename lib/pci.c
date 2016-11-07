/*
 * Copyright (C) 2013, Red Hat Inc, Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <linux/pci_regs.h>
#include "pci.h"
#include "asm/pci.h"

bool pci_dev_exists(pcidevaddr_t dev)
{
	return (pci_config_readw(dev, PCI_VENDOR_ID) != 0xffff &&
		pci_config_readw(dev, PCI_DEVICE_ID) != 0xffff);
}

/* Scan bus look for a specific device. Only bus 0 scanned for now. */
pcidevaddr_t pci_find_dev(uint16_t vendor_id, uint16_t device_id)
{
	pcidevaddr_t dev;

	for (dev = 0; dev < 256; ++dev) {
		if (pci_config_readw(dev, PCI_VENDOR_ID) == vendor_id &&
		    pci_config_readw(dev, PCI_DEVICE_ID) == device_id)
			return dev;
	}

	return PCIDEVADDR_INVALID;
}

uint32_t pci_bar_mask(uint32_t bar)
{
	return (bar & PCI_BASE_ADDRESS_SPACE_IO) ?
		PCI_BASE_ADDRESS_IO_MASK : PCI_BASE_ADDRESS_MEM_MASK;
}

uint32_t pci_bar_get(pcidevaddr_t dev, int bar_num)
{
	return pci_config_readl(dev, PCI_BASE_ADDRESS_0 + bar_num * 4);
}

phys_addr_t pci_bar_get_addr(pcidevaddr_t dev, int bar_num)
{
	uint32_t bar = pci_bar_get(dev, bar_num);
	uint32_t mask = pci_bar_mask(bar);
	uint64_t addr = bar & mask;

	if (pci_bar_is64(dev, bar_num))
		addr |= (uint64_t)pci_bar_get(dev, bar_num + 1) << 32;

	return pci_translate_addr(dev, addr);
}

void pci_bar_set_addr(pcidevaddr_t dev, int bar_num, phys_addr_t addr)
{
	int off = PCI_BASE_ADDRESS_0 + bar_num * 4;

	pci_config_writel(dev, off, (uint32_t)addr);

	if (pci_bar_is64(dev, bar_num))
		pci_config_writel(dev, off + 4, (uint32_t)(addr >> 32));
}

/*
 * To determine the amount of address space needed by a PCI device,
 * one must save the original value of the BAR, write a value of
 * all 1's to the register, and then read it back. The amount of
 * memory can be then determined by masking the information bits,
 * performing a bitwise NOT, and incrementing the value by 1.
 *
 * The following pci_bar_size_helper() and pci_bar_size() functions
 * implement the algorithm.
 */
static uint32_t pci_bar_size_helper(pcidevaddr_t dev, int bar_num)
{
	int off = PCI_BASE_ADDRESS_0 + bar_num * 4;
	uint32_t bar, val;

	bar = pci_config_readl(dev, off);
	pci_config_writel(dev, off, ~0u);
	val = pci_config_readl(dev, off);
	pci_config_writel(dev, off, bar);

	return val;
}

phys_addr_t pci_bar_size(pcidevaddr_t dev, int bar_num)
{
	uint32_t bar, size;

	size = pci_bar_size_helper(dev, bar_num);
	if (!size)
		return 0;

	bar = pci_bar_get(dev, bar_num);
	size &= pci_bar_mask(bar);

	if (pci_bar_is64(dev, bar_num)) {
		phys_addr_t size64 = pci_bar_size_helper(dev, bar_num + 1);
		size64 = (size64 << 32) | size;

		return ~size64 + 1;
	} else {
		return ~size + 1;
	}
}

bool pci_bar_is_memory(pcidevaddr_t dev, int bar_num)
{
	uint32_t bar = pci_bar_get(dev, bar_num);

	return !(bar & PCI_BASE_ADDRESS_SPACE_IO);
}

bool pci_bar_is_valid(pcidevaddr_t dev, int bar_num)
{
	return pci_bar_get(dev, bar_num);
}

bool pci_bar_is64(pcidevaddr_t dev, int bar_num)
{
	uint32_t bar = pci_bar_get(dev, bar_num);

	if (bar & PCI_BASE_ADDRESS_SPACE_IO)
		return false;

	return (bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
		      PCI_BASE_ADDRESS_MEM_TYPE_64;
}

void pci_bar_print(pcidevaddr_t dev, int bar_num)
{
	phys_addr_t size, start, end;
	uint32_t bar;

	size = pci_bar_size(dev, bar_num);
	if (!size)
		return;

	bar = pci_bar_get(dev, bar_num);
	start = pci_bar_get_addr(dev, bar_num);
	end = start + size - 1;

	if (pci_bar_is64(dev, bar_num)) {
		printf("BAR#%d,%d [%" PRIx64 "-%" PRIx64 " ",
		       bar_num, bar_num + 1, start, end);
	} else {
		printf("BAR#%d [%02x-%02x ",
		       bar_num, (uint32_t)start, (uint32_t)end);
	}

	if (bar & PCI_BASE_ADDRESS_SPACE_IO) {
		printf("PIO");
	} else {
		printf("MEM");
		switch (bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK) {
		case PCI_BASE_ADDRESS_MEM_TYPE_32:
			printf("32");
			break;
		case PCI_BASE_ADDRESS_MEM_TYPE_1M:
			printf("1M");
			break;
		case PCI_BASE_ADDRESS_MEM_TYPE_64:
			printf("64");
			break;
		default:
			assert(0);
		}
	}

	if (bar & PCI_BASE_ADDRESS_MEM_PREFETCH)
		printf("/p");

	printf("]");
}

void pci_dev_print_id(pcidevaddr_t dev)
{
	printf("00.%02x.%1x %04x:%04x", dev / 8, dev % 8,
		pci_config_readw(dev, PCI_VENDOR_ID),
		pci_config_readw(dev, PCI_DEVICE_ID));
}

static void pci_dev_print(pcidevaddr_t dev)
{
	uint8_t header = pci_config_readb(dev, PCI_HEADER_TYPE);
	uint8_t progif = pci_config_readb(dev, PCI_CLASS_PROG);
	uint8_t subclass = pci_config_readb(dev, PCI_CLASS_DEVICE);
	uint8_t class = pci_config_readb(dev, PCI_CLASS_DEVICE + 1);
	int i;

	pci_dev_print_id(dev);
	printf(" type %02x progif %02x class %02x subclass %02x\n",
	       header, progif, class, subclass);

	if ((header & PCI_HEADER_TYPE_MASK) != PCI_HEADER_TYPE_NORMAL)
		return;

	for (i = 0; i < 6; i++) {
		if (pci_bar_size(dev, i)) {
			printf("\t");
			pci_bar_print(dev, i);
			printf("\n");
		}
		if (pci_bar_is64(dev, i))
			i++;
	}
}

void pci_print(void)
{
	pcidevaddr_t dev;

	for (dev = 0; dev < 256; ++dev) {
		if (pci_dev_exists(dev))
			pci_dev_print(dev);
	}
}
