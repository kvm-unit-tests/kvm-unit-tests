#ifndef __ASMARM64_MMU_H_
#define __ASMARM64_MMU_H_
/*
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

static inline bool mmu_enabled(void)
{
	return false;
}

static inline void mmu_enable_idmap(void)
{
}

#endif /* __ASMARM64_MMU_H_ */
