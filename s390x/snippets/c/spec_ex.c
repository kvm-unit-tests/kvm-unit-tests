// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright IBM Corp. 2021
 *
 * Snippet used by specification exception interception test.
 */
#include <libcflat.h>
#include <bitops.h>
#include <asm/arch_def.h>

__attribute__((section(".text"))) int main(void)
{
	uint64_t bad_psw = 0;

	/* PSW bit 12 has no name or meaning and must be 0 */
	lowcore.pgm_new_psw.mask = BIT(63 - 12);
	lowcore.pgm_new_psw.addr = 0xdeadbeee;
	asm volatile ("lpsw %0" :: "Q"(bad_psw));
	return 0;
}
