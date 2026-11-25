#ifndef _ASMX86_PCI_H_
#define _ASMX86_PCI_H_
/*
 * Copyright (C) 2013, Red Hat Inc, Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "pci.h"
#include "x86/asm/io.h"

/*
 * Bits [1:0] offset into data port, not address port. Spec compliant host
 * bridges ignore them in CONFIG_ADDRESS, but QEMU does not; mask them out here
 * so QEMU doesn't double-offset the access.
 */
#define PCI_CONF1_ADDRESS(dev, reg)	((0x1 << 31) | ((dev) << 8) | ((reg) & ~3))

/* Ensure access offset + size stays within the 4-byte (DWORD) boundary. */
#define ASSERT_PCI_CONF1_VALID(reg, type) \
	assert(((reg) & 3) + sizeof(type) <= 4)

static inline uint8_t pci_config_readb(pcidevaddr_t dev, uint8_t reg)
{
    outl(PCI_CONF1_ADDRESS(dev, reg), 0xCF8);
    return inb(0xCFC + (reg & 3));
}

static inline uint16_t pci_config_readw(pcidevaddr_t dev, uint8_t reg)
{
    ASSERT_PCI_CONF1_VALID(reg, uint16_t);
    outl(PCI_CONF1_ADDRESS(dev, reg), 0xCF8);
    return inw(0xCFC + (reg & 3));
}

static inline uint32_t pci_config_readl(pcidevaddr_t dev, uint8_t reg)
{
    ASSERT_PCI_CONF1_VALID(reg, uint32_t);
    outl(PCI_CONF1_ADDRESS(dev, reg), 0xCF8);
    return inl(0xCFC);
}

static inline void pci_config_writeb(pcidevaddr_t dev, uint8_t reg,
                                     uint8_t val)
{
    outl(PCI_CONF1_ADDRESS(dev, reg), 0xCF8);
    outb(val, 0xCFC + (reg & 3));
}

static inline void pci_config_writew(pcidevaddr_t dev, uint8_t reg,
                                     uint16_t val)
{
    ASSERT_PCI_CONF1_VALID(reg, uint16_t);
    outl(PCI_CONF1_ADDRESS(dev, reg), 0xCF8);
    outw(val, 0xCFC + (reg & 3));
}

static inline void pci_config_writel(pcidevaddr_t dev, uint8_t reg,
                                     uint32_t val)
{
    ASSERT_PCI_CONF1_VALID(reg, uint32_t);
    outl(PCI_CONF1_ADDRESS(dev, reg), 0xCF8);
    outl(val, 0xCFC);
}

static inline
phys_addr_t pci_translate_addr(pcidevaddr_t dev __unused, uint64_t addr)
{
    return addr;
}

#endif
