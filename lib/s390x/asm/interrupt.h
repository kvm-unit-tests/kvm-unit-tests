/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#ifndef _ASMS390X_IRQ_H_
#define _ASMS390X_IRQ_H_
#include <asm/arch_def.h>

void handle_pgm_int(void);
void expect_pgm_int(void);
void check_pgm_int_code(uint16_t code);

/* Activate low-address protection */
static inline void low_prot_enable(void)
{
	uint64_t cr0;

	asm volatile (" stctg %%c0,%%c0,%0 " : : "Q"(cr0) : "memory");
	cr0 |= 1ULL << (63-35);
	asm volatile (" lctlg %%c0,%%c0,%0 " : : "Q"(cr0));
}

/* Disable low-address protection */
static inline void low_prot_disable(void)
{
	uint64_t cr0;

	asm volatile (" stctg %%c0,%%c0,%0 " : : "Q"(cr0) : "memory");
	cr0 &= ~(1ULL << (63-35));
	asm volatile (" lctlg %%c0,%%c0,%0 " : : "Q"(cr0));
}

#endif
