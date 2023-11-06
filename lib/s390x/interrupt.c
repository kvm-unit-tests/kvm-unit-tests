/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * s390x interrupt handling
 *
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 */
#include <libcflat.h>
#include <asm/barrier.h>
#include <asm/mem.h>
#include <asm/asm-offsets.h>
#include <sclp.h>
#include <interrupt.h>
#include <sie.h>
#include <fault.h>
#include <asm/page.h>
#include "smp.h"

/**
 * expect_pgm_int - Expect a program interrupt on the current CPU.
 */
void expect_pgm_int(void)
{
	THIS_CPU->pgm_int_expected = true;
	lowcore.pgm_int_code = 0;
	lowcore.trans_exc_id = 0;
	mb();
}

/**
 * expect_ext_int - Expect an external interrupt on the current CPU.
 */
void expect_ext_int(void)
{
	THIS_CPU->ext_int_expected = true;
	lowcore.ext_int_code = 0;
	mb();
}

/**
 * clear_pgm_int - Clear program interrupt information
 *
 * Clear program interrupt information, including the expected program
 * interrupt flag.
 * No program interrupts are expected after calling this function.
 *
 * Return: the program interrupt code before clearing
 */
uint16_t clear_pgm_int(void)
{
	uint16_t code;

	mb();
	code = lowcore.pgm_int_code;
	lowcore.pgm_int_code = 0;
	lowcore.trans_exc_id = 0;
	THIS_CPU->pgm_int_expected = false;
	return code;
}

/**
 * check_pgm_int_code - Check the program interrupt code on the current CPU.
 * @code: the expected program interrupt code on the current CPU
 *
 * Check and report if the program interrupt on the current CPU matches the
 * expected one.
 */
void check_pgm_int_code(uint16_t code)
{
	mb();
	report(code == lowcore.pgm_int_code,
	       "Program interrupt: expected(%d) == received(%d)", code,
	       lowcore.pgm_int_code);
}

/**
 * register_pgm_cleanup_func - Register a cleanup function for progam
 * interrupts for the current CPU.
 * @f: the cleanup function to be registered on the current CPU
 *
 * Register a cleanup function to be called at the end of the normal
 * interrupt handling for program interrupts for this CPU.
 *
 * Pass NULL to unregister a previously registered cleanup function.
 */
void register_pgm_cleanup_func(void (*f)(struct stack_frame_int *))
{
	THIS_CPU->pgm_cleanup_func = f;
}

/**
 * register_ext_cleanup_func - Register a cleanup function for external
 * interrupts for the current CPU.
 * @f: the cleanup function to be registered on the current CPU
 *
 * Register a cleanup function to be called at the end of the normal
 * interrupt handling for external interrupts for this CPU.
 *
 * Pass NULL to unregister a previously registered cleanup function.
 */
void register_ext_cleanup_func(void (*f)(struct stack_frame_int *))
{
	THIS_CPU->ext_cleanup_func = f;
}

/**
 * irq_set_dat_mode - Set the DAT mode of all interrupt handlers, except for
 * restart.
 * @use_dat: specifies whether to use DAT or not
 * @as: specifies the address space mode to use. Not set if use_dat is false.
 *
 * This will update the DAT mode and address space mode of all interrupt new
 * PSWs.
 *
 * Since enabling DAT needs initialized CRs and the restart new PSW is often used
 * to initialize CRs, the restart new PSW is never touched to avoid the chicken
 * and egg situation.
 */
void irq_set_dat_mode(bool use_dat, enum address_space as)
{
	struct psw* irq_psws[] = {
		OPAQUE_PTR(GEN_LC_EXT_NEW_PSW),
		OPAQUE_PTR(GEN_LC_SVC_NEW_PSW),
		OPAQUE_PTR(GEN_LC_PGM_NEW_PSW),
		OPAQUE_PTR(GEN_LC_MCCK_NEW_PSW),
		OPAQUE_PTR(GEN_LC_IO_NEW_PSW),
	};
	struct psw *psw;

	assert(as == AS_PRIM || as == AS_ACCR || as == AS_SECN || as == AS_HOME);

	for (size_t i = 0; i < ARRAY_SIZE(irq_psws); i++) {
		psw = irq_psws[i];
		psw->dat = use_dat;
		if (use_dat)
			psw->as = as;
	}
}

static void fixup_pgm_int(struct stack_frame_int *stack)
{
	/* If we have an error on SIE we directly move to sie_exit */
	if (lowcore.pgm_old_psw.addr >= (uint64_t)&sie_entry &&
	    lowcore.pgm_old_psw.addr <= (uint64_t)&sie_exit) {
		lowcore.pgm_old_psw.addr = (uint64_t)&sie_exit;
		return;
	}

	switch (lowcore.pgm_int_code) {
	case PGM_INT_CODE_PRIVILEGED_OPERATION:
		/* Normal operation is in supervisor state, so this exception
		 * was produced intentionally and we should return to the
		 * supervisor state.
		 */
		lowcore.pgm_old_psw.mask &= ~PSW_MASK_PSTATE;
		break;
	case PGM_INT_CODE_PROTECTION:
		/* Handling for iep.c test case. */
		if (prot_is_iep((union teid) { .val = lowcore.trans_exc_id }))
			/*
			 * We branched to the instruction that caused
			 * the exception so we can use the return
			 * address in GR14 to jump back and continue
			 * executing test code.
			 */
			lowcore.pgm_old_psw.addr = stack->grs0[12];
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
	case PGM_INT_CODE_SECURE_STOR_ACCESS:
	case PGM_INT_CODE_NON_SECURE_STOR_ACCESS:
	case PGM_INT_CODE_SECURE_STOR_VIOLATION:
		/* The interrupt was nullified, the old PSW points at the
		 * responsible instruction. Forward the PSW so we don't loop.
		 */
		lowcore.pgm_old_psw.addr += lowcore.pgm_int_id;
	}
	/* suppressed/terminated/completed point already at the next address */
}

static void print_storage_exception_information(void)
{
	switch (lowcore.pgm_int_code) {
	case PGM_INT_CODE_PROTECTION:
	case PGM_INT_CODE_PAGE_TRANSLATION:
	case PGM_INT_CODE_SEGMENT_TRANSLATION:
	case PGM_INT_CODE_ASCE_TYPE:
	case PGM_INT_CODE_REGION_FIRST_TRANS:
	case PGM_INT_CODE_REGION_SECOND_TRANS:
	case PGM_INT_CODE_REGION_THIRD_TRANS:
	case PGM_INT_CODE_SECURE_STOR_ACCESS:
	case PGM_INT_CODE_NON_SECURE_STOR_ACCESS:
	case PGM_INT_CODE_SECURE_STOR_VIOLATION:
		print_decode_teid(lowcore.trans_exc_id);
		break;
	}
}

static void print_int_regs(struct stack_frame_int *stack, bool sie)
{
	struct kvm_s390_sie_block *sblk;

	printf("\n");
	printf("%s\n", sie ? "Guest registers:" : "Host registers:");
	printf("GPRS:\n");
	printf("%016lx %016lx %016lx %016lx\n",
	       stack->grs1[0], stack->grs1[1], stack->grs0[0], stack->grs0[1]);
	printf("%016lx %016lx %016lx %016lx\n",
	       stack->grs0[2], stack->grs0[3], stack->grs0[4], stack->grs0[5]);
	printf("%016lx %016lx %016lx %016lx\n",
	       stack->grs0[6], stack->grs0[7], stack->grs0[8], stack->grs0[9]);

	if (sie) {
		sblk = (struct kvm_s390_sie_block *)stack->grs0[12];
		printf("%016lx %016lx %016lx %016lx\n",
		       stack->grs0[10], stack->grs0[11], sblk->gg14, sblk->gg15);
	} else {
		printf("%016lx %016lx %016lx %016lx\n",
		       stack->grs0[10], stack->grs0[11], stack->grs0[12], stack->grs0[13]);
	}

	printf("\n");
}

static void print_pgm_info(struct stack_frame_int *stack)

{
	bool in_sie, in_sie_gregs;
	struct vm_save_area *vregs;

	in_sie = (lowcore.pgm_old_psw.addr >= (uintptr_t)sie_entry &&
		  lowcore.pgm_old_psw.addr <= (uintptr_t)sie_exit);
	in_sie_gregs = (lowcore.pgm_old_psw.addr >= (uintptr_t)sie_entry_gregs &&
			lowcore.pgm_old_psw.addr < (uintptr_t)sie_exit_gregs);

	printf("\n");
	printf("Unexpected program interrupt %s: %#x on cpu %d at %#lx, ilen %d\n",
	       in_sie ? "in SIE" : "",
	       lowcore.pgm_int_code, stap(), lowcore.pgm_old_psw.addr, lowcore.pgm_int_id);

	/*
	 * If we fall out of SIE before loading the host registers,
	 * then we need to do it here so we print the host registers
	 * and not the guest registers.
	 *
	 * Back tracing is actually not a problem since SIE restores gr15.
	 */
	if (in_sie_gregs) {
		print_int_regs(stack, true);
		vregs = *((struct vm_save_area **)(stack->grs0[13] + __SF_SIE_SAVEAREA));

		/*
		 * The grs are not linear on the interrupt stack frame.
		 * We copy 0 and 1 here and 2 - 15 with the memcopy below.
		 */
		stack->grs1[0] = vregs->host.grs[0];
		stack->grs1[1] = vregs->host.grs[1];
		/*  2 - 15 */
		memcpy(stack->grs0, &vregs->host.grs[2], sizeof(stack->grs0) - 8);
	}
	print_int_regs(stack, false);
	dump_stack();

	/* Dump stack doesn't end with a \n so we add it here instead */
	printf("\n");
	print_storage_exception_information();
	report_summary();
	abort();
}

void handle_pgm_int(struct stack_frame_int *stack)
{
	if (THIS_CPU->in_interrupt_handler) {
		/* Something went very wrong, stop everything now without printing anything */
		smp_teardown();
		disabled_wait(0xfa12edbad21);
	}
	if (!THIS_CPU->pgm_int_expected) {
		/* Force sclp_busy to false, otherwise we will loop forever */
		sclp_handle_ext();
		print_pgm_info(stack);
	}

	THIS_CPU->pgm_int_expected = false;
	THIS_CPU->in_interrupt_handler = true;

	if (THIS_CPU->pgm_cleanup_func)
		THIS_CPU->pgm_cleanup_func(stack);
	else
		fixup_pgm_int(stack);
	THIS_CPU->in_interrupt_handler = false;
}

void handle_ext_int(struct stack_frame_int *stack)
{
	THIS_CPU->in_interrupt_handler = true;
	if (!THIS_CPU->ext_int_expected && lowcore.ext_int_code != EXT_IRQ_SERVICE_SIG) {
		report_abort("Unexpected external call interrupt (code %#x): on cpu %d at %#lx",
			     lowcore.ext_int_code, stap(), lowcore.ext_old_psw.addr);
		return;
	}

	if (lowcore.ext_int_code == EXT_IRQ_SERVICE_SIG) {
		stack->crs[0] &= ~(1UL << 9);
		sclp_handle_ext();
	} else {
		THIS_CPU->ext_int_expected = false;
	}

	if (!(stack->crs[0] & CR0_EXTM_MASK))
		lowcore.ext_old_psw.mask &= ~PSW_MASK_EXT;

	if (THIS_CPU->ext_cleanup_func)
		THIS_CPU->ext_cleanup_func(stack);
	THIS_CPU->in_interrupt_handler = false;
}

void handle_mcck_int(void)
{
	report_abort("Unexpected machine check interrupt: on cpu %d at %#lx",
		     stap(), lowcore.mcck_old_psw.addr);
}

static void (*io_int_func)(void);

void handle_io_int(void)
{
	THIS_CPU->in_interrupt_handler = true;
	if (io_int_func)
		io_int_func();
	else
		report_abort("Unexpected io interrupt: on cpu %d at %#lx",
			     stap(), lowcore.io_old_psw.addr);
	THIS_CPU->in_interrupt_handler = false;
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
	uint16_t code = lowcore.svc_int_code;

	switch (code) {
	case SVC_LEAVE_PSTATE:
		lowcore.svc_old_psw.mask &= ~PSW_MASK_PSTATE;
		break;
	default:
		report_abort("Unexpected supervisor call interrupt: code %#x on cpu %d at %#lx",
			      code, stap(), lowcore.svc_old_psw.addr);
	}
}
