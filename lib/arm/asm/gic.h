/*
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#ifndef _ASMARM_GIC_H_
#define _ASMARM_GIC_H_

#include <asm/gic-v2.h>

/* Distributor registers */
#define GICD_CTLR			0x0000
#define GICD_TYPER			0x0004
#define GICD_ISENABLER			0x0100
#define GICD_IPRIORITYR			0x0400

#define GICD_TYPER_IRQS(typer)		((((typer) & 0x1f) + 1) * 32)
#define GICD_INT_EN_SET_SGI		0x0000ffff
#define GICD_INT_DEF_PRI_X4		0xa0a0a0a0

/* CPU interface registers */
#define GICC_CTLR			0x0000
#define GICC_PMR			0x0004

#define GICC_INT_PRI_THRESHOLD		0xf0

#ifndef __ASSEMBLY__

/*
 * gic_init will try to find all known gics, and then
 * initialize the gic data for the one found.
 * returns
 *  0   : no gic was found
 *  > 0 : the gic version of the gic found
 */
extern int gic_init(void);

#endif /* !__ASSEMBLY__ */
#endif /* _ASMARM_GIC_H_ */
