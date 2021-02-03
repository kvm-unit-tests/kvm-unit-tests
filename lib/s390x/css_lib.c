/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Channel Subsystem tests library
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 */
#include <libcflat.h>
#include <alloc_phys.h>
#include <asm/page.h>
#include <string.h>
#include <interrupt.h>
#include <asm/arch_def.h>
#include <asm/time.h>
#include <asm/arch_def.h>
#include <alloc_page.h>
#include <malloc_io.h>
#include <css.h>

struct schib schib;
struct chsc_scsc *chsc_scsc;

static const char * const chsc_rsp_description[] = {
	"CHSC unknown error",
	"Command executed",
	"Invalid command",
	"Request-block error",
	"Command not installed",
	"Data not available",
	"Absolute address of channel-subsystem communication block exceeds 2G - 1.",
	"Invalid command format",
	"Invalid channel-subsystem identification (CSSID)",
	"The command-request block specified an invalid format for the command response block.",
	"Invalid subchannel-set identification (SSID)",
	"A busy condition precludes execution.",
};

static bool check_response(void *p)
{
	struct chsc_header *h = p;

	if (h->code == CHSC_RSP_OK)
		return true;

	if (h->code > CHSC_RSP_MAX)
		h->code = 0;

	report_abort("Response code %04x: %s", h->code,
		      chsc_rsp_description[h->code]);
	return false;
}

bool chsc(void *p, uint16_t code, uint16_t len)
{
	struct chsc_header *h = p;

	h->code = code;
	h->len = len;

	switch (_chsc(p)) {
	case 3:
		report_abort("Subchannel invalid or not enabled.");
		break;
	case 2:
		report_abort("CHSC subchannel busy.");
		break;
	case 1:
		report_abort("Subchannel invalid or not enabled.");
		break;
	case 0:
		return check_response(p + len);
	}
	return false;
}

bool get_chsc_scsc(void)
{
	int i, n;
	char buffer[510];
	char *p;

	if (chsc_scsc) /* chsc_scsc already initialized */
		return true;

	chsc_scsc = alloc_page();
	if (!chsc_scsc) {
		report_abort("could not allocate chsc_scsc page!");
		return false;
	}

	if (!chsc(chsc_scsc, CHSC_SCSC, CHSC_SCSC_LEN))
		return false;

	for (i = 0, p = buffer; i < CSS_GENERAL_FEAT_BITLEN; i++) {
		if (css_test_general_feature(i)) {
			n = snprintf(p, sizeof(buffer), "%d,", i);
			p += n;
		}
	}
	report_info("General features: %s", buffer);

	for (i = 0, p = buffer; i < CSS_CHSC_FEAT_BITLEN; i++) {
		if (css_test_chsc_feature(i)) {
			n = snprintf(p, sizeof(buffer), "%d,", i);
			p += n;
		}
	}
	report_info("CHSC features: %s", buffer);

	return true;
}

/*
 * css_enumerate:
 * On success return the first subchannel ID found.
 * On error return an invalid subchannel ID containing cc
 */
int css_enumerate(void)
{
	struct pmcw *pmcw = &schib.pmcw;
	int scn_found = 0;
	int dev_found = 0;
	int schid = 0;
	int cc;
	int scn;

	for (scn = 0; scn < 0xffff; scn++) {
		cc = stsch(scn | SCHID_ONE, &schib);
		switch (cc) {
		case 0:		/* 0 means SCHIB stored */
			break;
		case 3:		/* 3 means no more channels */
			goto out;
		default:	/* 1 or 2 should never happen for STSCH */
			report_abort("Unexpected error %d on subchannel %08x",
				     cc, scn | SCHID_ONE);
			return cc;
		}

		/* We currently only support type 0, a.k.a. I/O channels */
		if (PMCW_CHANNEL_TYPE(pmcw) != 0)
			continue;

		/* We ignore I/O channels without valid devices */
		scn_found++;
		if (!(pmcw->flags & PMCW_DNV))
			continue;

		/* We keep track of the first device as our test device */
		if (!schid)
			schid = scn | SCHID_ONE;
		report_info("Found subchannel %08x", scn | SCHID_ONE);
		dev_found++;
	}

out:
	report_info("Tested subchannels: %d, I/O subchannels: %d, I/O devices: %d",
		    scn, scn_found, dev_found);
	return schid;
}

/*
 * css_enabled: report if the subchannel is enabled
 * @schid: Subchannel Identifier
 * Return value:
 *   true if the subchannel is enabled
 *   false otherwise
 */
bool css_enabled(int schid)
{
	struct pmcw *pmcw = &schib.pmcw;
	int cc;

	cc = stsch(schid, &schib);
	if (cc) {
		report_info("stsch: updating sch %08x failed with cc=%d",
			    schid, cc);
		return false;
	}

	if (!(pmcw->flags & PMCW_ENABLE)) {
		report_info("stsch: sch %08x not enabled", schid);
		return false;
	}
	return true;
}
/*
 * css_enable: enable the subchannel with the specified ISC
 * @schid: Subchannel Identifier
 * @isc  : number of the interruption subclass to use
 * Return value:
 *   On success: 0
 *   On error the CC of the faulty instruction
 *      or -1 if the retry count is exceeded.
 */
int css_enable(int schid, int isc)
{
	struct pmcw *pmcw = &schib.pmcw;
	int retry_count = 0;
	uint16_t flags;
	int cc;

	/* Read the SCHIB for this subchannel */
	cc = stsch(schid, &schib);
	if (cc) {
		report_info("stsch: sch %08x failed with cc=%d", schid, cc);
		return cc;
	}

	flags = PMCW_ENABLE | (isc << PMCW_ISC_SHIFT);
	if ((pmcw->flags & (PMCW_ISC_MASK | PMCW_ENABLE)) == flags) {
		report_info("stsch: sch %08x already enabled", schid);
		return 0;
	}

retry:
	/* Update the SCHIB to enable the channel and set the ISC */
	pmcw->flags &= ~PMCW_ISC_MASK;
	pmcw->flags |= flags;

	/* Tell the CSS we want to modify the subchannel */
	cc = msch(schid, &schib);
	if (cc) {
		/*
		 * If the subchannel is status pending or
		 * if a function is in progress,
		 * we consider both cases as errors.
		 */
		report_info("msch: sch %08x failed with cc=%d", schid, cc);
		return cc;
	}

	/*
	 * Read the SCHIB again to verify the enablement
	 */
	if (css_enabled(schid))
		return 0;

	if (retry_count++ < MAX_ENABLE_RETRIES) {
		mdelay(10); /* the hardware was not ready, give it some time */
		goto retry;
	}

	report_info("msch: modifying sch %08x failed after %d retries. pmcw flags: %04x",
		    schid, retry_count, pmcw->flags);
	return -1;
}

/*
 * schib_update_mb: update the subchannel Measurement Block
 * @schid: Subchannel Identifier
 * @mb   : 64bit address of the measurement block
 * @mbi : the measurement block offset
 * @flags : PMCW_MBUE to enable measurement block update
 *	    PMCW_DCTME to enable device connect time
 *	    0 to disable measurement
 * @format1: set if format 1 is to be used
 */
static bool schib_update_mb(int schid, uint64_t mb, uint16_t mbi,
			    uint16_t flags, bool format1)
{
	struct pmcw *pmcw = &schib.pmcw;
	int cc;

	/* Read the SCHIB for this subchannel */
	cc = stsch(schid, &schib);
	if (cc) {
		report_info("stsch: sch %08x failed with cc=%d", schid, cc);
		return false;
	}

	/* Update the SCHIB to enable the measurement block */
	if (flags) {
		pmcw->flags |= flags;

		if (format1)
			pmcw->flags2 |= PMCW_MBF1;
		else
			pmcw->flags2 &= ~PMCW_MBF1;

		pmcw->mbi = mbi;
		schib.mbo = mb & ~0x3f;
	} else {
		pmcw->flags &= ~(PMCW_MBUE | PMCW_DCTME);
	}

	/* Tell the CSS we want to modify the subchannel */
	cc = msch(schid, &schib);
	if (cc) {
		/*
		 * If the subchannel is status pending or
		 * if a function is in progress,
		 * we consider both cases as errors.
		 */
		report_info("msch: sch %08x failed with cc=%d", schid, cc);
		return false;
	}

	/*
	 * Read the SCHIB again
	 */
	cc = stsch(schid, &schib);
	if (cc) {
		report_info("stsch: updating sch %08x failed with cc=%d",
			    schid, cc);
		return false;
	}

	return true;
}

/*
 * css_enable_mb: enable the subchannel Measurement Block
 * @schid: Subchannel Identifier
 * @mb   : 64bit address of the measurement block
 * @format1: set if format 1 is to be used
 * @mbi : the measurement block offset
 * @flags : PMCW_MBUE to enable measurement block update
 *	    PMCW_DCTME to enable device connect time
 */
bool css_enable_mb(int schid, uint64_t mb, uint16_t mbi, uint16_t flags,
		   bool format1)
{
	int retry_count = MAX_ENABLE_RETRIES;
	struct pmcw *pmcw = &schib.pmcw;

	while (retry_count-- &&
	       !schib_update_mb(schid, mb, mbi, flags, format1))
		mdelay(10); /* the hardware was not ready, give it some time */

	return schib.mbo == mb && pmcw->mbi == mbi;
}

/*
 * css_disable_mb: disable the subchannel Measurement Block
 * @schid: Subchannel Identifier
 */
bool css_disable_mb(int schid)
{
	int retry_count = MAX_ENABLE_RETRIES;

	while (retry_count-- &&
	       !schib_update_mb(schid, 0, 0, 0, 0))
		mdelay(10); /* the hardware was not ready, give it some time */

	return retry_count > 0;
}

static struct irb irb;

void css_irq_io(void)
{
	int ret = 0;
	char *flags;
	int sid;

	report_prefix_push("Interrupt");
	sid = lowcore_ptr->subsys_id_word;
	/* Lowlevel set the SID as interrupt parameter. */
	if (lowcore_ptr->io_int_param != sid) {
		report(0,
		       "io_int_param: %x differs from subsys_id_word: %x",
		       lowcore_ptr->io_int_param, sid);
		goto pop;
	}
	report_prefix_pop();

	report_prefix_push("tsch");
	ret = tsch(sid, &irb);
	switch (ret) {
	case 1:
		dump_irb(&irb);
		flags = dump_scsw_flags(irb.scsw.ctrl);
		report(0,
		       "I/O interrupt, but tsch returns CC 1 for subchannel %08x. SCSW flags: %s",
		       sid, flags);
		break;
	case 2:
		report(0, "tsch returns unexpected CC 2");
		break;
	case 3:
		report(0, "tsch reporting sch %08x as not operational", sid);
		break;
	case 0:
		/* Stay humble on success */
		break;
	}
pop:
	report_prefix_pop();
	lowcore_ptr->io_old_psw.mask &= ~PSW_MASK_WAIT;
}

int start_ccw1_chain(unsigned int sid, struct ccw1 *ccw)
{
	struct orb orb = {
		.intparm = sid,
		.ctrl = ORB_CTRL_ISIC|ORB_CTRL_FMT|ORB_LPM_DFLT,
		.cpa = (unsigned int) (unsigned long)ccw,
	};

	return ssch(sid, &orb);
}

struct ccw1 *ccw_alloc(int code, void *data, int count, unsigned char flags)
{
	struct ccw1 *ccw;

	ccw = alloc_io_mem(sizeof(*ccw), 0);
	if (!ccw)
		return NULL;

	ccw->code = code;
	ccw->flags = flags;
	ccw->count = count;
	ccw->data_address = (int)(unsigned long)data;

	return ccw;
}

/* wait_and_check_io_completion:
 * @schid: the subchannel ID
 *
 * Makes the most common check to validate a successful I/O
 * completion.
 * Only report failures.
 */
int wait_and_check_io_completion(int schid)
{
	int ret = 0;

	wait_for_interrupt(PSW_MASK_IO);

	report_prefix_push("check I/O completion");

	if (lowcore_ptr->io_int_param != schid) {
		report(0, "interrupt parameter: expected %08x got %08x",
		       schid, lowcore_ptr->io_int_param);
		ret = -1;
		goto end;
	}

	/* Verify that device status is valid */
	if (!(irb.scsw.ctrl & SCSW_SC_PENDING)) {
		report(0, "No status pending after interrupt. Subch Ctrl: %08x",
		       irb.scsw.ctrl);
		ret = -1;
		goto end;
	}

	if (!(irb.scsw.ctrl & (SCSW_SC_SECONDARY | SCSW_SC_PRIMARY))) {
		report(0, "Primary or secondary status missing. Subch Ctrl: %08x",
		       irb.scsw.ctrl);
		ret = -1;
		goto end;
	}

	if (!(irb.scsw.dev_stat & (SCSW_DEVS_DEV_END | SCSW_DEVS_SCH_END))) {
		report(0, "No device end or sch end. Dev. status: %02x",
		       irb.scsw.dev_stat);
		ret = -1;
		goto end;
	}

	if (irb.scsw.sch_stat & ~SCSW_SCHS_IL) {
		report_info("Unexpected Subch. status %02x", irb.scsw.sch_stat);
		ret = -1;
		goto end;
	}

end:
	report_prefix_pop();
	return ret;
}

/*
 * css_residual_count
 * Return the residual count, if it is valid.
 *
 * Return value:
 * Success: the residual count
 * Not meaningful: -1 (-1 can not be a valid count)
 */
int css_residual_count(unsigned int schid)
{

	if (!(irb.scsw.ctrl & (SCSW_SC_PENDING | SCSW_SC_PRIMARY)))
		return -1;

	if (irb.scsw.dev_stat)
		if (irb.scsw.sch_stat & ~(SCSW_SCHS_PCI | SCSW_SCHS_IL))
			return -1;

	return irb.scsw.count;
}

/*
 * enable_io_isc: setup ISC in Control Register 6
 * @isc: The interruption Sub Class as a bitfield
 */
void enable_io_isc(uint8_t isc)
{
	uint64_t value;

	value = (uint64_t)isc << 24;
	lctlg(6, value);
}
