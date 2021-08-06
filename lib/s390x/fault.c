/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Library to decode addressing related exceptions
 *
 * Copyright 2021 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <bitops.h>
#include <asm/arch_def.h>
#include <asm/page.h>
#include <fault.h>

static struct lowcore *lc = (struct lowcore *)0x0;

/* Decodes the protection exceptions we'll most likely see */
static void print_decode_pgm_prot(uint64_t teid)
{
	if (prot_is_lap(teid)) {
		printf("Type: LAP\n");
		return;
	}

	if (prot_is_iep(teid)) {
		printf("Type: IEP\n");
		return;
	}

	if (prot_is_datp(teid)) {
		printf("Type: DAT\n");
		return;
	}
}

void print_decode_teid(uint64_t teid)
{
	int asce_id = teid & 3;
	bool dat = lc->pgm_old_psw.mask & PSW_MASK_DAT;

	printf("Memory exception information:\n");
	printf("DAT: %s\n", dat ? "on" : "off");

	printf("AS: ");
	switch (asce_id) {
	case AS_PRIM:
		printf("Primary\n");
		break;
	case AS_ACCR:
		printf("Access Register\n");
		break;
	case AS_SECN:
		printf("Secondary\n");
		break;
	case AS_HOME:
		printf("Home\n");
		break;
	}

	if (lc->pgm_int_code == PGM_INT_CODE_PROTECTION)
		print_decode_pgm_prot(teid);

	/*
	 * If teid bit 61 is off for these two exception the reported
	 * address is unpredictable.
	 */
	if ((lc->pgm_int_code == PGM_INT_CODE_SECURE_STOR_ACCESS ||
	     lc->pgm_int_code == PGM_INT_CODE_SECURE_STOR_VIOLATION) &&
	    !test_bit_inv(61, &teid)) {
		printf("Address: %lx, unpredictable\n ", teid & PAGE_MASK);
		return;
	}
	printf("TEID: %lx\n", teid);
	printf("Address: %lx\n\n", teid & PAGE_MASK);
}
