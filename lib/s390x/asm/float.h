/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2018 Red Hat Inc
 *
 * Authors:
 *  David Hildenbrand <david@redhat.com>
 */
#ifndef _ASMS390X_FLOAT_H_
#define _ASMS390X_FLOAT_H_

static inline void set_fpc(uint32_t fpc)
{
	asm volatile("	lfpc	%0\n" : : "m"(fpc) );
}

static inline uint32_t get_fpc(void)
{
	uint32_t fpc;

	asm volatile("	stfpc	%0\n" : "=m"(fpc));

	return fpc;
}

static inline uint8_t get_fpc_dxc(void)
{
	return get_fpc() >> 8;
}

static inline void set_fpc_dxc(uint8_t dxc)
{
	uint32_t fpc = get_fpc();

	fpc = (fpc & ~0xff00) | ((uint32_t)dxc) << 8;

	set_fpc(fpc);
}

static inline void afp_enable(void)
{
	ctl_set_bit(0, CTL0_AFP);
}

static inline void afp_disable(void)
{
	ctl_clear_bit(0, CTL0_AFP);
}

#endif
