#ifndef _ASMARM_THREAD_INFO_H_
#define _ASMARM_THREAD_INFO_H_
/*
 * Adapted from arch/arm64/include/asm/thread_info.h
 *
 * Copyright (C) 2015, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/processor.h>
#include <asm/page.h>

#define __MIN_THREAD_SIZE	16384
#if PAGE_SIZE > __MIN_THREAD_SIZE
#define THREAD_SIZE		PAGE_SIZE
#else
#define THREAD_SIZE		__MIN_THREAD_SIZE
#endif
#define THREAD_START_SP		(THREAD_SIZE - 16)

#define TIF_USER_MODE		(1U << 0)

struct thread_info {
	int cpu;
	unsigned int flags;
#ifdef __arm__
	exception_fn exception_handlers[EXCPTN_MAX];
#else
	vector_fn vector_handlers[VECTOR_MAX];
	exception_fn exception_handlers[VECTOR_MAX][EC_MAX];
#endif
	char ext[0];		/* allow unit tests to add extended info */
};

static inline struct thread_info *thread_info_sp(unsigned long sp)
{
	return (struct thread_info *)(sp & ~(THREAD_SIZE - 1));
}

register unsigned long current_stack_pointer asm("sp");

static inline struct thread_info *current_thread_info(void)
{
	return thread_info_sp(current_stack_pointer);
}

extern void thread_info_init(struct thread_info *ti, unsigned int flags);

#endif /* _ASMARM_THREAD_INFO_H_ */
