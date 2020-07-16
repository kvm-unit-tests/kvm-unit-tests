/*
 * Channel Subsystem tests library
 *
 * Copyright (c) 2020 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */
#include <libcflat.h>
#include <alloc_phys.h>
#include <asm/page.h>
#include <string.h>
#include <interrupt.h>
#include <asm/arch_def.h>

#include <css.h>

static struct schib schib;

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
