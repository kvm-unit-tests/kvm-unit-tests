/*
 * Copyright (C) 2013, Red Hat Inc, Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <linux/pci_regs.h>
#include "pci.h"
#include "asm/pci.h"

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

static uint32_t pci_bar_get(pcidevaddr_t dev, int bar_num)
{
	return pci_config_readl(dev, PCI_BASE_ADDRESS_0 + bar_num * 4);
}

unsigned long pci_bar_addr(pcidevaddr_t dev, int bar_num)
{
	uint32_t bar = pci_bar_get(dev, bar_num);

	if (bar & PCI_BASE_ADDRESS_SPACE_IO)
		return bar & PCI_BASE_ADDRESS_IO_MASK;
	else
		return bar & PCI_BASE_ADDRESS_MEM_MASK;
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
