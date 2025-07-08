#ifndef _ASMX86_BITOPS_H_
#define _ASMX86_BITOPS_H_

#ifndef _BITOPS_H_
#error only <bitops.h> can be included directly
#endif

#ifdef __x86_64__
#define BITS_PER_LONG	64
#else
#define BITS_PER_LONG	32
#endif

#define HAVE_BUILTIN_FLS 1

/*
 * Macros to generate condition code outputs from inline assembly,
 * The output operand must be type "bool".
 */
#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
#else
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c) [_cc_ ## c] "=qm"
#endif

static inline void __clear_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;

	__asm__ __volatile__("btr %1, %0"
			     : "+m" (*addr) : "Ir" (bit) : "cc", "memory");
}

static inline void __set_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;

	__asm__ __volatile__("bts %1, %0"
			     : "+m" (*addr) : "Ir" (bit) : "cc", "memory");
}

static inline bool __test_and_clear_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;
	bool v;

	__asm__ __volatile__("btr %2, %1" CC_SET(c)
			     : CC_OUT(c) (v), "+m" (*addr) : "Ir" (bit));
	return v;
}

static inline bool __test_and_set_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;
	bool v;

	__asm__ __volatile__("bts %2, %1" CC_SET(c)
			     : CC_OUT(c) (v), "+m" (*addr) : "Ir" (bit));
	return v;
}

static inline void clear_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;

	__asm__ __volatile__("lock; btr %1, %0"
			     : "+m" (*addr) : "Ir" (bit) : "cc", "memory");
}

static inline void set_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;

	__asm__ __volatile__("lock; bts %1, %0"
			     : "+m" (*addr) : "Ir" (bit) : "cc", "memory");
}

static inline bool test_and_clear_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;
	bool v;

	__asm__ __volatile__("lock; btr %2, %1" CC_SET(c)
			     : CC_OUT(c) (v), "+m" (*addr) : "Ir" (bit));
	return v;
}

static inline bool test_and_set_bit(int bit, void *__addr)
{
	unsigned long *addr = __addr;
	bool v;

	__asm__ __volatile__("lock; bts %2, %1" CC_SET(c)
			     : CC_OUT(c) (v), "+m" (*addr) : "Ir" (bit));
	return v;
}

#endif
