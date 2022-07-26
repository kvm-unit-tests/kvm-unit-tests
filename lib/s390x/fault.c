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


static void print_decode_pgm_prot(union teid teid)
{
	switch (get_supp_on_prot_facility()) {
	case SOP_NONE:
	case SOP_BASIC:
		printf("Type: ?\n"); /* modern/relevant machines have ESOP */
		break;
	case SOP_ENHANCED_1:
		if (teid.sop_teid_predictable) {/* implies access list or DAT */
			if (teid.sop_acc_list)
				printf("Type: ACC\n");
			else
				printf("Type: DAT\n");
		} else {
			printf("Type: KEY or LAP\n");
		}
		break;
	case SOP_ENHANCED_2: {
		static const char * const prot_str[] = {
			"KEY or LAP",
			"DAT",
			"KEY",
			"ACC",
			"LAP",
			"IEP",
		};
		_Static_assert(ARRAY_SIZE(prot_str) == PROT_NUM_CODES, "ESOP2 prot codes");
		int prot_code = teid_esop2_prot_code(teid);

		printf("Type: %s\n", prot_str[prot_code]);
		}
	}
}

void print_decode_teid(uint64_t raw_teid)
{
	union teid teid = { .val = raw_teid };
	bool dat = lowcore.pgm_old_psw.mask & PSW_MASK_DAT;

	printf("Memory exception information:\n");
	printf("DAT: %s\n", dat ? "on" : "off");

	printf("AS: ");
	switch (teid.asce_id) {
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

	if (lowcore.pgm_int_code == PGM_INT_CODE_PROTECTION)
		print_decode_pgm_prot(teid);

	/*
	 * If teid bit 61 is off for these two exception the reported
	 * address is unpredictable.
	 */
	if ((lowcore.pgm_int_code == PGM_INT_CODE_SECURE_STOR_ACCESS ||
	     lowcore.pgm_int_code == PGM_INT_CODE_SECURE_STOR_VIOLATION) &&
	    !teid.sop_teid_predictable) {
		printf("Address: %lx, unpredictable\n ", raw_teid & PAGE_MASK);
		return;
	}
	printf("TEID: %lx\n", raw_teid);
	printf("Address: %lx\n\n", raw_teid & PAGE_MASK);
}
