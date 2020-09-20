/*
 * s390x interrupt handling
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#include <libcflat.h>
#include <asm/barrier.h>
#include <sclp.h>
#include <interrupt.h>

static bool pgm_int_expected;
static bool ext_int_expected;
static void (*pgm_cleanup_func)(void);
static struct lowcore *lc;

void expect_pgm_int(void)
{
	pgm_int_expected = true;
	lc->pgm_int_code = 0;
	mb();
}

void expect_ext_int(void)
{
	ext_int_expected = true;
	lc->ext_int_code = 0;
	mb();
}

uint16_t clear_pgm_int(void)
{
	uint16_t code;

	mb();
	code = lc->pgm_int_code;
	lc->pgm_int_code = 0;
	pgm_int_expected = false;
	return code;
}

void check_pgm_int_code(uint16_t code)
{
	mb();
	report(code == lc->pgm_int_code,
	       "Program interrupt: expected(%d) == received(%d)", code,
	       lc->pgm_int_code);
}

void register_pgm_cleanup_func(void (*f)(void))
{
	pgm_cleanup_func = f;
}

static void fixup_pgm_int(void)
{
	switch (lc->pgm_int_code) {
	case PGM_INT_CODE_PRIVILEGED_OPERATION:
		/* Normal operation is in supervisor state, so this exception
		 * was produced intentionally and we should return to the
		 * supervisor state.
		 */
		lc->pgm_old_psw.mask &= ~PSW_MASK_PSTATE;
		break;
	case PGM_INT_CODE_PROTECTION:
		/* Handling for iep.c test case. */
		if (lc->trans_exc_id & 0x80UL && lc->trans_exc_id & 0x04UL &&
		    !(lc->trans_exc_id & 0x08UL))
			lc->pgm_old_psw.addr = lc->sw_int_grs[14];
		break;
	case PGM_INT_CODE_SEGMENT_TRANSLATION:
	case PGM_INT_CODE_PAGE_TRANSLATION:
	case PGM_INT_CODE_TRACE_TABLE:
	case PGM_INT_CODE_AFX_TRANSLATION:
	case PGM_INT_CODE_ASX_TRANSLATION:
	case PGM_INT_CODE_LX_TRANSLATION:
	case PGM_INT_CODE_EX_TRANSLATION:
	case PGM_INT_CODE_PRIMARY_AUTHORITY:
	case PGM_INT_CODE_SECONDARY_AUTHORITY:
	case PGM_INT_CODE_LFX_TRANSLATION:
	case PGM_INT_CODE_LSX_TRANSLATION:
	case PGM_INT_CODE_ALEN_TRANSLATION:
	case PGM_INT_CODE_ALE_SEQUENCE:
	case PGM_INT_CODE_ASTE_VALIDITY:
	case PGM_INT_CODE_ASTE_SEQUENCE:
	case PGM_INT_CODE_EXTENDED_AUTHORITY:
	case PGM_INT_CODE_LSTE_SEQUENCE:
	case PGM_INT_CODE_ASTE_INSTANCE:
	case PGM_INT_CODE_STACK_FULL:
	case PGM_INT_CODE_STACK_EMPTY:
	case PGM_INT_CODE_STACK_SPECIFICATION:
	case PGM_INT_CODE_STACK_TYPE:
	case PGM_INT_CODE_STACK_OPERATION:
	case PGM_INT_CODE_ASCE_TYPE:
	case PGM_INT_CODE_REGION_FIRST_TRANS:
	case PGM_INT_CODE_REGION_SECOND_TRANS:
	case PGM_INT_CODE_REGION_THIRD_TRANS:
	case PGM_INT_CODE_PER:
	case PGM_INT_CODE_CRYPTO_OPERATION:
		/* The interrupt was nullified, the old PSW points at the
		 * responsible instruction. Forward the PSW so we don't loop.
		 */
		lc->pgm_old_psw.addr += lc->pgm_int_id;
	}
	/* suppressed/terminated/completed point already at the next address */
}

void handle_pgm_int(void)
{
	if (!pgm_int_expected) {
		/* Force sclp_busy to false, otherwise we will loop forever */
		sclp_handle_ext();
		report_abort("Unexpected program interrupt: %d on cpu %d at %#lx, ilen %d\n",
			     lc->pgm_int_code, stap(), lc->pgm_old_psw.addr,
			     lc->pgm_int_id);
	}

	pgm_int_expected = false;

	if (pgm_cleanup_func)
		(*pgm_cleanup_func)();
	else
		fixup_pgm_int();
}

void handle_ext_int(void)
{
	if (!ext_int_expected &&
	    lc->ext_int_code != EXT_IRQ_SERVICE_SIG) {
		report_abort("Unexpected external call interrupt (code %#x): on cpu %d at %#lx",
			     lc->ext_int_code, stap(), lc->ext_old_psw.addr);
		return;
	}

	if (lc->ext_int_code == EXT_IRQ_SERVICE_SIG) {
		lc->sw_int_crs[0] &= ~(1UL << 9);
		sclp_handle_ext();
	} else {
		ext_int_expected = false;
	}

	if (!(lc->sw_int_crs[0] & CR0_EXTM_MASK))
		lc->ext_old_psw.mask &= ~PSW_MASK_EXT;
}

void handle_mcck_int(void)
{
	report_abort("Unexpected machine check interrupt: on cpu %d at %#lx",
		     stap(), lc->mcck_old_psw.addr);
}

static void (*io_int_func)(void);

void handle_io_int(void)
{
	if (io_int_func)
		return io_int_func();

	report_abort("Unexpected io interrupt: on cpu %d at %#lx",
		     stap(), lc->io_old_psw.addr);
}

int register_io_int_func(void (*f)(void))
{
	if (io_int_func)
		return -1;
	io_int_func = f;
	return 0;
}

int unregister_io_int_func(void (*f)(void))
{
	if (io_int_func != f)
		return -1;
	io_int_func = NULL;
	return 0;
}

void handle_svc_int(void)
{
	report_abort("Unexpected supervisor call interrupt: on cpu %d at %#lx",
		     stap(), lc->svc_old_psw.addr);
}
