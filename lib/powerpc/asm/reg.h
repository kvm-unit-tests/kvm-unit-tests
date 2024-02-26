#ifndef _ASMPOWERPC_REG_H
#define _ASMPOWERPC_REG_H

#include <linux/const.h>

#define UL(x) _AC(x, UL)

#define SPR_TB		0x10c
#define SPR_SPRG0	0x110
#define SPR_SPRG1	0x111
#define SPR_SPRG2	0x112
#define SPR_SPRG3	0x113
#define SPR_PVR		0x11f
#define   PVR_VERSION_MASK	UL(0xffff0000)
#define   PVR_VER_970		UL(0x00390000)
#define   PVR_VER_970FX		UL(0x003c0000)
#define   PVR_VER_970MP		UL(0x00440000)
#define   PVR_VER_POWER8E	UL(0x004b0000)
#define   PVR_VER_POWER8NVL	UL(0x004c0000)
#define   PVR_VER_POWER8	UL(0x004d0000)
#define   PVR_VER_POWER9	UL(0x004e0000)
#define   PVR_VER_POWER10	UL(0x00800000)
#define SPR_HSRR0	0x13a
#define SPR_HSRR1	0x13b

/* Machine State Register definitions: */
#define MSR_EE_BIT	15			/* External Interrupts Enable */
#define MSR_SF_BIT	63			/* 64-bit mode */

#endif
