#ifndef _ASMARM_THREAD_INFO_H_
#define _ASMARM_THREAD_INFO_H_
/*
 * Adapted from arch/arm64/include/asm/thread_info.h
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#define THREAD_SIZE		16384
#define THREAD_START_SP		(THREAD_SIZE - 16)

struct thread_info {
	int cpu;
	char ext[0];		/* allow unit tests to add extended info */
};

register unsigned long current_stack_pointer asm("sp");

static inline struct thread_info *current_thread_info(void)
{
	return (struct thread_info *)
		(current_stack_pointer & ~(THREAD_SIZE - 1));
}

#endif /* _ASMARM_THREAD_INFO_H_ */
