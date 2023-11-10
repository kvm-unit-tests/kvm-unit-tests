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

union teid {
	unsigned long val;
	union {
		/* common fields DAT exc & protection exc */
		struct {
			uint64_t addr			: 52 -  0;
			uint64_t acc_exc_fetch_store	: 54 - 52;
			uint64_t side_effect_acc	: 55 - 54;
			uint64_t /* reserved */		: 62 - 55;
			uint64_t asce_id		: 64 - 62;
		};
		/* DAT exc */
		struct {
			uint64_t /* pad */		: 61 -  0;
			uint64_t dat_move_page		: 62 - 61;
		};
		/* suppression on protection */
		struct {
			uint64_t /* pad */		: 60 -  0;
			uint64_t sop_acc_list		: 61 - 60;
			uint64_t sop_teid_predictable	: 62 - 61;
		};
		/* enhanced suppression on protection 2 */
		struct {
			uint64_t /* pad */		: 56 -  0;
			uint64_t esop2_prot_code_0	: 57 - 56;
			uint64_t /* pad */		: 60 - 57;
			uint64_t esop2_prot_code_1	: 61 - 60;
			uint64_t esop2_prot_code_2	: 62 - 61;
		};
	};
};

enum prot_code {
	PROT_KEY_OR_LAP,
	PROT_DAT,
	PROT_KEY,
	PROT_ACC_LIST,
	PROT_LAP,
	PROT_IEP,
	PROT_NUM_CODES /* Must always be last */
};

static inline enum prot_code teid_esop2_prot_code(union teid teid)
{
	int code = (teid.esop2_prot_code_0 << 2 |
		    teid.esop2_prot_code_1 << 1 |
		    teid.esop2_prot_code_2);

	assert(code < PROT_NUM_CODES);
	return (enum prot_code)code;
}

void register_pgm_cleanup_func(void (*f)(struct stack_frame_int *));
void register_ext_cleanup_func(void (*f)(struct stack_frame_int *));
void handle_pgm_int(struct stack_frame_int *stack);
void handle_ext_int(struct stack_frame_int *stack);
void handle_mcck_int(void);
void handle_io_int(void);
void handle_svc_int(void);
void expect_pgm_int(void);
void expect_ext_int(void);
uint16_t clear_pgm_int(void);
void check_pgm_int_code(uint16_t code);

void irq_set_dat_mode(bool use_dat, enum address_space as);

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

/**
 * read_pgm_int_code - Get the program interruption code of the last pgm int
 * on the current CPU.
 *
 * This is similar to clear_pgm_int(), except that it doesn't clear the
 * interruption information from lowcore.
 *
 * Return: 0 when none occurred.
 */
static inline uint16_t read_pgm_int_code(void)
{
	return lowcore.pgm_int_code;
}

#endif
