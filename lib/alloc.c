#include "alloc.h"
#include "asm/page.h"

void *malloc(size_t size)
{
	return memalign(sizeof(long), size);
}

static bool mult_overflow(size_t a, size_t b)
{
#if BITS_PER_LONG == 32
	/* 32 bit system, easy case: just use u64 */
	return (u64)a * (u64)b >= (1ULL << 32);
#else
#ifdef __SIZEOF_INT128__
	/* if __int128 is available use it (like the u64 case above) */
	unsigned __int128 res = a;
	res *= b;
	res >>= 64;
	return res != 0;
#else
	u64 tmp;

	if ((a >> 32) && (b >> 32))
		return true;
	if (!(a >> 32) && !(b >> 32))
		return false;
	tmp = (u32)a;
	tmp *= (u32)b;
	tmp >>= 32;
	if (a < b)
		tmp += a * (b >> 32);
	else
		tmp += b * (a >> 32);
	return tmp >> 32;
#endif /* __SIZEOF_INT128__ */
#endif /* BITS_PER_LONG == 32 */
}

void *calloc(size_t nmemb, size_t size)
{
	void *ptr;

	assert(!mult_overflow(nmemb, size));
	ptr = malloc(nmemb * size);
	if (ptr)
		memset(ptr, 0, nmemb * size);
	return ptr;
}

#define METADATA_EXTRA	(2 * sizeof(uintptr_t))
#define OFS_SLACK	(-2 * sizeof(uintptr_t))
#define OFS_SIZE	(-sizeof(uintptr_t))

static inline void *block_begin(void *mem)
{
	uintptr_t slack = *(uintptr_t *)(mem + OFS_SLACK);
	return mem - slack;
}

static inline uintptr_t block_size(void *mem)
{
	return *(uintptr_t *)(mem + OFS_SIZE);
}

void free(void *ptr)
{
	if (!alloc_ops->free)
		return;

	void *base = block_begin(ptr);
	uintptr_t sz = block_size(ptr);

	alloc_ops->free(base, sz);
}

void *memalign(size_t alignment, size_t size)
{
	void *p;
	uintptr_t blkalign;
	uintptr_t mem;

	if (!size)
		return NULL;

	assert(alignment >= sizeof(void *) && is_power_of_2(alignment));
	assert(alloc_ops && alloc_ops->memalign);

	size += alignment - 1;
	blkalign = MAX(alignment, alloc_ops->align_min);
	size = ALIGN(size + METADATA_EXTRA, alloc_ops->align_min);
	p = alloc_ops->memalign(blkalign, size);
	assert(p);

	/* Leave room for metadata before aligning the result.  */
	mem = (uintptr_t)p + METADATA_EXTRA;
	mem = ALIGN(mem, alignment);

	/* Write the metadata */
	*(uintptr_t *)(mem + OFS_SLACK) = mem - (uintptr_t)p;
	*(uintptr_t *)(mem + OFS_SIZE) = size;
	return (void *)mem;
}
