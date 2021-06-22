/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 */
#ifndef _ASMS390X_IRQ_H_
#define _ASMS390X_IRQ_H_
#include <asm/arch_def.h>

#define EXT_IRQ_EMERGENCY_SIG	0x1201
#define EXT_IRQ_EXTERNAL_CALL	0x1202
#define EXT_IRQ_SERVICE_SIG	0x2401

#define TEID_ASCE_PRIMARY	0
#define TEID_ASCE_AR		1
#define TEID_ASCE_SECONDARY	2
#define TEID_ASCE_HOME		3

union teid {
	unsigned long val;
	struct {
		unsigned long addr:52;
		unsigned long fetch:1;
		unsigned long store:1;
		unsigned long reserved:6;
		unsigned long acc_list_prot:1;
		/*
		 * depending on the exception and the installed facilities,
		 * the m field can indicate several different things,
		 * including whether the exception was triggered by a MVPG
		 * instruction, or whether the addr field is meaningful
		 */
		unsigned long m:1;
		unsigned long asce_id:2;
	};
};

void register_pgm_cleanup_func(void (*f)(void));
void handle_pgm_int(struct stack_frame_int *stack);
void handle_ext_int(struct stack_frame_int *stack);
void handle_mcck_int(void);
void handle_io_int(void);
void handle_svc_int(void);
void expect_pgm_int(void);
void expect_ext_int(void);
uint16_t clear_pgm_int(void);
void check_pgm_int_code(uint16_t code);

/* Activate low-address protection */
static inline void low_prot_enable(void)
{
	ctl_set_bit(0, CTL0_LOW_ADDR_PROT);
}

/* Disable low-address protection */
static inline void low_prot_disable(void)
{
	ctl_clear_bit(0, CTL0_LOW_ADDR_PROT);
}

#endif
