#ifndef _ASMPOWERPC_REG_H
#define _ASMPOWERPC_REG_H

#include <linux/const.h>

#define UL(x) _AC(x, UL)

#define SPR_DSISR	0x012
#define SPR_DAR		0x013
#define SPR_DEC		0x016
#define SPR_SRR0	0x01a
#define SPR_SRR1	0x01b
#define   SRR1_PREFIX		UL(0x20000000)
#define SPR_PIDR	0x030
#define SPR_FSCR	0x099
#define   FSCR_PREFIX		UL(0x2000)
#define SPR_HFSCR	0x0be
#define SPR_TB		0x10c
#define SPR_SPRG0	0x110
#define SPR_SPRG1	0x111
#define SPR_SPRG2	0x112
#define SPR_SPRG3	0x113
#define SPR_TBU40	0x11e
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
#define SPR_HDEC	0x136
#define SPR_HSRR0	0x13a
#define SPR_HSRR1	0x13b
#define SPR_LPCR	0x13e
#define   LPCR_HDICE		UL(0x1)
#define   LPCR_LD		UL(0x20000)
#define SPR_LPIDR	0x13f
#define SPR_HEIR	0x153
#define SPR_PTCR	0x1d0
#define SPR_MMCR0	0x31b
#define   MMCR0_FC		UL(0x80000000)
#define   MMCR0_PMAE		UL(0x04000000)
#define   MMCR0_PMAO		UL(0x00000080)
#define SPR_SIAR	0x31c

/* Machine State Register definitions: */
#define MSR_LE_BIT	0
#define MSR_EE_BIT	15			/* External Interrupts Enable */
#define MSR_HV_BIT	60			/* Hypervisor mode */
#define MSR_SF_BIT	63			/* 64-bit mode */

#define MSR_DR		UL(0x0010)
#define MSR_IR		UL(0x0020)
#define MSR_BE		UL(0x0200)		/* Branch Trace Enable */
#define MSR_SE		UL(0x0400)		/* Single Step Enable */
#define MSR_EE		UL(0x8000)
#define MSR_ME		UL(0x1000)
#define MSR_PR		UL(0x4000)

#endif
