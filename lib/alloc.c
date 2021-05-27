#include "alloc.h"
#include "asm/page.h"
#include "bitops.h"

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
