/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <alloc.h>
#include <bitops.h>
#include <asm/page.h>
#include <linux/compiler.h>

void *malloc(size_t size)
{
	return memalign(sizeof(long), size);
}

void *calloc(size_t nmemb, size_t size)
{
	void *ptr;

	assert(!check_mul_overflow(nmemb, size));
	ptr = malloc(nmemb * size);
	if (ptr)
		memset(ptr, 0, nmemb * size);
	return ptr;
}

void free(void *ptr)
{
	if (alloc_ops->free)
		alloc_ops->free(ptr);
}

void *memalign(size_t alignment, size_t size)
{
	void *p;

	if (!size)
		return NULL;

	assert(is_power_of_2(alignment));
	assert(alloc_ops && alloc_ops->memalign);

	p = alloc_ops->memalign(alignment, size);
	assert(p);

	return (void *)p;
}
