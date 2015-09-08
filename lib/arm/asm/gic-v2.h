/*
 * All GIC* defines are lifted from include/linux/irqchip/arm-gic.h
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#ifndef _ASMARM_GIC_V2_H_
#define _ASMARM_GIC_V2_H_

#ifndef _ASMARM_GIC_H_
#error Do not directly include <asm/gic-v2.h>. Include <asm/gic.h>
#endif

#define GICD_ENABLE			0x1

#define GICC_ENABLE			0x1
#define GICC_IAR_INT_ID_MASK		0x3ff

#ifndef __ASSEMBLY__

struct gicv2_data {
	void *dist_base;
	void *cpu_base;
	unsigned int irq_nr;
};
extern struct gicv2_data gicv2_data;

#define gicv2_dist_base()		(gicv2_data.dist_base)
#define gicv2_cpu_base()		(gicv2_data.cpu_base)

extern int gicv2_init(void);
extern void gicv2_enable_defaults(void);

#endif /* !__ASSEMBLY__ */
#endif /* _ASMARM_GIC_V2_H_ */
