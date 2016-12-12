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

extern bool pci_probe(void);
extern void pci_print(void);
extern bool pci_dev_exists(pcidevaddr_t dev);
extern pcidevaddr_t pci_find_dev(uint16_t vendor_id, uint16_t device_id);

/*
 * @bar_num in all BAR access functions below is the index of the 32-bit
 * register starting from the PCI_BASE_ADDRESS_0 offset.
 *
 * In cases where the BAR size is 64-bit, a caller should still provide
 * @bar_num in terms of 32-bit words. For example, if a device has a 64-bit
 * BAR#0 and a 32-bit BAR#1, then caller should provide 2 to address BAR#1,
 * not 1.
 *
 * It is expected the caller is aware of the device BAR layout and never
 * tries to address the middle of a 64-bit register.
 */
extern phys_addr_t pci_bar_get_addr(pcidevaddr_t dev, int bar_num);
extern void pci_bar_set_addr(pcidevaddr_t dev, int bar_num, phys_addr_t addr);
extern phys_addr_t pci_bar_size(pcidevaddr_t dev, int bar_num);
extern uint32_t pci_bar_get(pcidevaddr_t dev, int bar_num);
extern uint32_t pci_bar_mask(uint32_t bar);
extern bool pci_bar_is64(pcidevaddr_t dev, int bar_num);
extern bool pci_bar_is_memory(pcidevaddr_t dev, int bar_num);
extern bool pci_bar_is_valid(pcidevaddr_t dev, int bar_num);
extern void pci_bar_print(pcidevaddr_t dev, int bar_num);
extern void pci_dev_print_id(pcidevaddr_t dev);

extern int pci_testdev(void);

/*
 * pci-testdev is a driver for the pci-testdev qemu pci device. The
 * device enables testing mmio and portio exits, and measuring their
 * speed.
 */
#define PCI_VENDOR_ID_REDHAT		0x1b36
#define PCI_DEVICE_ID_REDHAT_TEST	0x0005

/*
 * pci-testdev supports at least three types of tests (via mmio and
 * portio BARs): no-eventfd, wildcard-eventfd and datamatch-eventfd
 */
#define PCI_TESTDEV_NUM_BARS		2
#define PCI_TESTDEV_NUM_TESTS		3

struct pci_test_dev_hdr {
	uint8_t  test;
	uint8_t  width;
	uint8_t  pad0[2];
	uint32_t offset;
	uint32_t data;
	uint32_t count;
	uint8_t  name[];
};

#define  PCI_HEADER_TYPE_MASK		0x7f

#endif /* PCI_H */
