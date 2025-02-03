/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright IBM Corp. 2023
 *
 * Snippet used by the STLFE interpretive execution facilities test.
 */
#include <libcflat.h>
#include <snippet-exit.h>

int main(void)
{
	const unsigned int max_fac_len = 8;
	uint64_t len_arg = max_fac_len - 1;
	uint64_t res[max_fac_len + 1];
	uint64_t fac[max_fac_len];

	asm volatile (" lgr	0,%[len]\n"
		"	stfle	%[fac]\n"
		"	lgr	%[len],0\n"
		: [fac] "=Q"(fac),
		  [len] "+d"(len_arg)
		:
		: "%r0", "cc"
	);
	res[0] = len_arg;
	memcpy(&res[1], fac, sizeof(fac));
	force_exit_value((uint64_t)&res);
	return 0;
}
