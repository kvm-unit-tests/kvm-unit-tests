#ifndef _ALLOC_H_
#define _ALLOC_H_
/*
 * alloc supplies three ingredients to the test framework that are all
 * related to the support of dynamic memory allocation.
 *
 * The first is a set of alloc function wrappers for malloc and its
 * friends. Using wrappers allows test code and common code to use the
 * same interface for memory allocation at all stages, even though the
 * implementations may change with the stage, e.g. pre/post paging.
 *
 * The second is a set of implementations for the alloc function
 * interfaces. These implementations are named early_*, as they can be
 * used almost immediately by the test framework.
 *
 * The third is a very simple physical memory allocator, which the
 * early_* alloc functions build on.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"

struct alloc_ops {
	void *(*memalign)(size_t alignment, size_t size);
};

extern struct alloc_ops *alloc_ops;

/*
 * Our malloc implementation is currently so simple that it can just
 * be inlined. :)
 */
static inline void *malloc(size_t size)
{
	assert(alloc_ops && alloc_ops->memalign);
	return alloc_ops->memalign(sizeof(long), size);
}

static inline void *calloc(size_t nmemb, size_t size)
{
	void *ptr = malloc(nmemb * size);
	if (ptr)
		memset(ptr, 0, nmemb * size);
	return ptr;
}

static inline void free(void *ptr)
{
}

static inline void *memalign(size_t alignment, size_t size)
{
	assert(alloc_ops && alloc_ops->memalign);
	return alloc_ops->memalign(alignment, size);
}

#endif /* _ALLOC_H_ */
