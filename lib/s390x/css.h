/*
 * CSS definitions
 *
 * Copyright IBM, Corp. 2020
 * Author: Pierre Morel <pmorel@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */

#ifndef CSS_H
#define CSS_H

/* subchannel ID bit 16 must always be one */
#define SCHID_ONE	0x00010000

#define CCW_F_CD	0x80
#define CCW_F_CC	0x40
#define CCW_F_SLI	0x20
#define CCW_F_SKP	0x10
#define CCW_F_PCI	0x08
#define CCW_F_IDA	0x04
#define CCW_F_S		0x02
#define CCW_F_MIDA	0x01

#define CCW_C_NOP	0x03
#define CCW_C_TIC	0x08

struct ccw1 {
	uint8_t code;
	uint8_t flags;
	uint16_t count;
	uint32_t data_address;
} __attribute__ ((aligned(8)));

#define ORB_CTRL_KEY	0xf0000000
#define ORB_CTRL_SPND	0x08000000
#define ORB_CTRL_STR	0x04000000
#define ORB_CTRL_MOD	0x02000000
#define ORB_CTRL_SYNC	0x01000000
#define ORB_CTRL_FMT	0x00800000
#define ORB_CTRL_PFCH	0x00400000
#define ORB_CTRL_ISIC	0x00200000
#define ORB_CTRL_ALCC	0x00100000
#define ORB_CTRL_SSIC	0x00080000
#define ORB_CTRL_CPTC	0x00040000
#define ORB_CTRL_C64	0x00020000
#define ORB_CTRL_I2K	0x00010000
#define ORB_CTRL_LPM	0x0000ff00
#define ORB_CTRL_ILS	0x00000080
#define ORB_CTRL_MIDAW	0x00000040
#define ORB_CTRL_ORBX	0x00000001

#define ORB_LPM_DFLT	0x00008000

struct orb {
	uint32_t intparm;
	uint32_t ctrl;
	uint32_t cpa;
	uint32_t prio;
	uint32_t reserved[4];
} __attribute__ ((aligned(4)));

struct scsw {
	uint32_t ctrl;
	uint32_t ccw_addr;
	uint8_t  dev_stat;
	uint8_t  sch_stat;
	uint16_t count;
};

struct pmcw {
	uint32_t intparm;
#define PMCW_DNV	0x0001
#define PMCW_ENABLE	0x0080
#define PMCW_ISC_MASK	0x3800
#define PMCW_ISC_SHIFT	11
	uint16_t flags;
	uint16_t devnum;
	uint8_t  lpm;
	uint8_t  pnom;
	uint8_t  lpum;
	uint8_t  pim;
	uint16_t mbi;
	uint8_t  pom;
	uint8_t  pam;
	uint8_t  chpid[8];
	uint32_t flags2;
};
#define PMCW_CHANNEL_TYPE(pmcw) (pmcw->flags2 >> 21)

struct schib {
	struct pmcw pmcw;
	struct scsw scsw;
	uint8_t  md[12];
} __attribute__ ((aligned(4)));

struct irb {
	struct scsw scsw;
	uint32_t esw[5];
	uint32_t ecw[8];
	uint32_t emw[8];
} __attribute__ ((aligned(4)));

/* CSS low level access functions */

static inline int ssch(unsigned long schid, struct orb *addr)
{
	register long long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	ssch	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (cc)
		: "d" (reg1), "a" (addr), "m" (*addr)
		: "cc", "memory");
	return cc;
}

static inline int stsch(unsigned long schid, struct schib *addr)
{
	register unsigned long reg1 asm ("1") = schid;
	int cc;

	asm volatile(
		"	stsch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc), "=m" (*addr)
		: "d" (reg1), "a" (addr)
		: "cc");
	return cc;
}

static inline int msch(unsigned long schid, struct schib *addr)
{
	register unsigned long reg1 asm ("1") = schid;
	int cc;

	asm volatile(
		"	msch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1), "m" (*addr), "a" (addr)
		: "cc");
	return cc;
}

static inline int tsch(unsigned long schid, struct irb *addr)
{
	register unsigned long reg1 asm ("1") = schid;
	int cc;

	asm volatile(
		"	tsch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc), "=m" (*addr)
		: "d" (reg1), "a" (addr)
		: "cc");
	return cc;
}

static inline int hsch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	hsch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int xsch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	xsch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int csch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	csch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int rsch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	rsch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int rchp(unsigned long chpid)
{
	register unsigned long reg1 asm("1") = chpid;
	int cc;

	asm volatile(
		"	rchp\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

/* Debug functions */
char *dump_pmcw_flags(uint16_t f);
char *dump_scsw_flags(uint32_t f);

void dump_scsw(struct scsw *scsw);
void dump_irb(struct irb *irbp);
void dump_schib(struct schib *sch);
struct ccw1 *dump_ccw(struct ccw1 *cp);
void dump_irb(struct irb *irbp);
void dump_pmcw(struct pmcw *p);
void dump_orb(struct orb *op);

int css_enumerate(void);
#define MAX_ENABLE_RETRIES      5

#define IO_SCH_ISC      3
int css_enable(int schid, int isc);
#endif
