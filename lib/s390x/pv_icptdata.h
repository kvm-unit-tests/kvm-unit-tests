/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Commonly used checks for PV SIE intercept data
 *
 * Copyright IBM Corp. 2023
 * Author: Janosch Frank <frankja@linux.ibm.com>
 */

#ifndef _S390X_PV_ICPTDATA_H_
#define _S390X_PV_ICPTDATA_H_

#include <sie.h>

/*
 * Checks the diagnose instruction intercept data for consistency with
 * the constants defined by the PV SIE architecture
 *
 * Supports: 0x44, 0x9c, 0x288, 0x308, 0x500
 */
static bool pv_icptdata_check_diag(struct vm *vm, int diag)
{
	int icptcode;

	switch (diag) {
	case 0x44:
	case 0x9c:
	case 0x288:
	case 0x308:
		icptcode = ICPT_PV_NOTIFY;
		break;
	case 0x500:
		icptcode = ICPT_PV_INSTR;
		break;
	default:
		/* If a new diag is introduced add it to the cases above! */
		assert(0);
	}

	return vm->sblk->icptcode == icptcode && vm->sblk->ipa == 0x8302 &&
	       vm->sblk->ipb == 0x50000000 && vm->save_area.guest.grs[5] == diag;
}
#endif
