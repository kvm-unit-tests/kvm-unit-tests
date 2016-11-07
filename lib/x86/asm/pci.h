#ifndef ASM_PCI_H
#define ASM_PCI_H
/*
 * Copyright (C) 2013, Red Hat Inc, Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "pci.h"
#include "x86/asm/io.h"

static inline uint32_t pci_config_readl(pcidevaddr_t dev, uint8_t reg)
{
    uint32_t index = reg | (dev << 8) | (0x1 << 31);
    outl(index, 0xCF8);
    return inl(0xCFC);
}

#endif
