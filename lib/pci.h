#ifndef PCI_H
#define PCI_H
/*
 * API for scanning a PCI bus for a given device, as well to access
 * BAR registers.
 *
 * Copyright (C) 2013, Red Hat Inc, Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"

typedef uint16_t pcidevaddr_t;
enum {
	PCIDEVADDR_INVALID = 0xffff,
};

extern pcidevaddr_t pci_find_dev(uint16_t vendor_id, uint16_t device_id);
extern unsigned long pci_bar_addr(pcidevaddr_t dev, int bar_num);
extern bool pci_bar_is_memory(pcidevaddr_t dev, int bar_num);
extern bool pci_bar_is_valid(pcidevaddr_t dev, int bar_num);

/*
 * pci-testdev is a driver for the pci-testdev qemu pci device. The
 * device enables testing mmio and portio exits, and measuring their
 * speed.
 */
#define PCI_VENDOR_ID_REDHAT		0x1b36
#define PCI_DEVICE_ID_REDHAT_TEST	0x0005

#define PCI_TESTDEV_NUM_BARS		2

struct pci_test_dev_hdr {
	uint8_t  test;
	uint8_t  width;
	uint8_t  pad0[2];
	uint32_t offset;
	uint32_t data;
	uint32_t count;
	uint8_t  name[];
};

#endif /* PCI_H */
