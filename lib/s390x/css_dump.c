/*
 * Channel subsystem structures dumping
 *
 * Copyright (c) 2020 IBM Corp.
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 *
 * Description:
 * Provides the dumping functions for various structures used by subchannels:
 * - ORB  : Operation request block, describes the I/O operation and points to
 *          a CCW chain
 * - CCW  : Channel Command Word, describes the command, data and flow control
 * - IRB  : Interuption response Block, describes the result of an operation;
 *          holds a SCSW and model-dependent data.
 * - SCHIB: SubCHannel Information Block composed of:
 *   - SCSW: SubChannel Status Word, status of the channel.
 *   - PMCW: Path Management Control Word
 * You need the QEMU ccw-pong device in QEMU to answer the I/O transfers.
 */

#include <libcflat.h>
#include <stdint.h>
#include <string.h>

#include <css.h>

/*
 * Try to have a more human representation of the SCSW flags:
 * each letter in the two strings represents the first
 * letter of the associated bit in the flag fields.
 */
static const char *scsw_str = "kkkkslccfpixuzen";
static const char *scsw_str2 = "1SHCrshcsdsAIPSs";
static char scsw_line[64] = {};

char *dump_scsw_flags(uint32_t f)
{
	int i;

	for (i = 0; i < 16; i++) {
		if ((f << i) & 0x80000000)
			scsw_line[i] = scsw_str[i];
		else
			scsw_line[i] = '_';
	}
	scsw_line[i] = ' ';
	for (; i < 32; i++) {
		if ((f << i) & 0x80000000)
			scsw_line[i + 1] = scsw_str2[i - 16];
		else
			scsw_line[i + 1] = '_';
	}
	return scsw_line;
}

/*
 * Try to have a more human representation of the PMCW flags
 * each letter in the string represents the first
 * letter of the associated bit in the flag fields.
 */
static const char *pmcw_str = "11iii111ellmmdtv";
static char pcmw_line[32] = {};
char *dump_pmcw_flags(uint16_t f)
{
	int i;

	for (i = 0; i < 16; i++) {
		if ((f << i) & 0x8000)
			pcmw_line[i] = pmcw_str[i];
		else
			pcmw_line[i] = '_';
	}
	return pcmw_line;
}

void dump_scsw(struct scsw *s)
{
	dump_scsw_flags(s->ctrl);
	printf("scsw->flags: %s\n", scsw_line);
	printf("scsw->addr : %08x\n", s->ccw_addr);
	printf("scsw->devs : %02x\n", s->dev_stat);
	printf("scsw->schs : %02x\n", s->sch_stat);
	printf("scsw->count: %04x\n", s->count);
}

void dump_irb(struct irb *irbp)
{
	int i;
	uint32_t *p = (uint32_t *)irbp;

	dump_scsw(&irbp->scsw);
	for (i = 0; i < sizeof(*irbp)/sizeof(*p); i++, p++)
		printf("irb[%02x] : %08x\n", i, *p);
}

void dump_pmcw(struct pmcw *p)
{
	int i;

	printf("pmcw->intparm  : %08x\n", p->intparm);
	printf("pmcw->flags    : %04x\n", p->flags);
	dump_pmcw_flags(p->flags);
	printf("pmcw->devnum   : %04x\n", p->devnum);
	printf("pmcw->lpm      : %02x\n", p->lpm);
	printf("pmcw->pnom     : %02x\n", p->pnom);
	printf("pmcw->lpum     : %02x\n", p->lpum);
	printf("pmcw->pim      : %02x\n", p->pim);
	printf("pmcw->mbi      : %04x\n", p->mbi);
	printf("pmcw->pom      : %02x\n", p->pom);
	printf("pmcw->pam      : %02x\n", p->pam);
	printf("pmcw->mbi      : %04x\n", p->mbi);
	for (i = 0; i < 8; i++)
		printf("pmcw->chpid[%d]: %02x\n", i, p->chpid[i]);
	printf("pmcw->flags2  : %08x\n", p->flags2);
}

void dump_schib(struct schib *sch)
{
	struct pmcw *p = &sch->pmcw;
	struct scsw *s = &sch->scsw;

	printf("--SCHIB--\n");
	dump_pmcw(p);
	dump_scsw(s);
}

struct ccw1 *dump_ccw(struct ccw1 *cp)
{
	printf("CCW: code: %02x flags: %02x count: %04x data: %08x\n", cp->code,
	    cp->flags, cp->count, cp->data_address);

	if (cp->code == CCW_C_TIC)
		return (struct ccw1 *)(long)cp->data_address;

	return (cp->flags & CCW_F_CC) ? cp + 1 : NULL;
}

void dump_orb(struct orb *op)
{
	struct ccw1 *cp;

	printf("ORB: intparm : %08x\n", op->intparm);
	printf("ORB: ctrl    : %08x\n", op->ctrl);
	printf("ORB: prio    : %08x\n", op->prio);
	cp = (struct ccw1 *)(long) (op->cpa);
	while (cp)
		cp = dump_ccw(cp);
}
