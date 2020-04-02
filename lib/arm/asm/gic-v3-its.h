/*
 * ITS 32-bit stubs
 *
 * Copyright (C) 2020, Red Hat Inc, Eric Auger <eric.auger@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#ifndef _ASMARM_GIC_V3_ITS_H_
#define _ASMARM_GIC_V3_ITS_H_

#ifndef _ASMARM_GIC_H_
#error Do not directly include <asm/gic-v3-its.h>. Include <asm/gic.h>
#endif

#include <libcflat.h>

/* dummy its_data struct to allow gic_get_dt_bases() call */
struct its_data {
	void *base;
};

static inline void its_init(void)
{
	assert_msg(false, "not supported on 32-bit");
}

#endif /* _ASMARM_GIC_V3_ITS_H_ */
