/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Functionality for SIE interception handling.
 *
 * Copyright IBM Corp. 2024
 */

#include <sie-icpt.h>

struct diag_itext sblk_ip_as_diag(struct kvm_s390_sie_block *sblk)
{
	union {
		struct {
			uint64_t ipa : 16;
			uint64_t ipb : 32;
			uint64_t     : 16;
		};
		struct diag_itext diag;
	} instr = { .ipa = sblk->ipa, .ipb = sblk->ipb };

	return instr.diag;
}

bool sie_is_diag_icpt(struct vm *vm, unsigned int diag)
{
	struct diag_itext instr = sblk_ip_as_diag(vm->sblk);
	uint8_t icptcode;
	uint64_t code;

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
		assert_msg(false, "unknown diag 0x%x", diag);
	}

	if (sie_is_pv(vm)) {
		if (instr.r_1 != 0 || instr.r_2 != 2 || instr.r_base != 5)
			return false;
		if (instr.displace)
			return false;
	} else {
		icptcode = ICPT_INST;
	}
	if (vm->sblk->icptcode != icptcode)
		return false;
	if (instr.opcode != 0x83 || instr.zero)
		return false;
	code = instr.r_base ? vm->save_area.guest.grs[instr.r_base] : 0;
	code = (code + instr.displace) & 0xffff;
	return code == diag;
}
