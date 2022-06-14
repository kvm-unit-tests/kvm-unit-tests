/* SPDX-License-Identifier: GPL-2.0 */
/*
 *    Copyright IBM Corp. 2017, 2022
 *    Author(s): Claudio Imbrenda <imbrenda@linux.vnet.ibm.com>
 *               Nico Boehr <nrb@linux.ibm.com>
 */
#include <asm/interrupt.h>

#ifndef PAGE_STATES_H
#define PAGE_STATES_H

#define ESSA_GET_STATE			0
#define ESSA_SET_STABLE			1
#define ESSA_SET_UNUSED			2
#define ESSA_SET_VOLATILE		3
#define ESSA_SET_POT_VOLATILE		4
#define ESSA_SET_STABLE_RESIDENT	5
#define ESSA_SET_STABLE_IF_RESIDENT	6
#define ESSA_SET_STABLE_NODAT		7

#define ESSA_MAX	ESSA_SET_STABLE_NODAT

#define ESSA_USAGE_STABLE		0
#define ESSA_USAGE_UNUSED		1
#define ESSA_USAGE_POT_VOLATILE		2
#define ESSA_USAGE_VOLATILE		3

static unsigned long essa(uint8_t state, unsigned long paddr)
{
	uint64_t extr_state;

	asm volatile(".insn rrf,0xb9ab0000,%[extr_state],%[addr],%[new_state],0" \
			: [extr_state] "=d" (extr_state) \
			: [addr] "a" (paddr), [new_state] "i" (state));

	return (unsigned long)extr_state;
}

/*
 * Unfortunately the availability is not indicated by stfl bits, but
 * we have to try to execute it and test for an operation exception.
 */
static inline bool check_essa_available(void)
{
	expect_pgm_int();
	essa(ESSA_GET_STATE, 0);
	return clear_pgm_int() == 0;
}

#endif
