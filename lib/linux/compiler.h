/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Taken from Linux commit 219d54332a09 ("Linux 5.4"), from the file
 * tools/include/linux/compiler.h, with minor changes.
 */
#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#ifndef __ASSEMBLY__

#include <stdint.h>

#define barrier()	asm volatile("" : : : "memory")

#define __always_inline	inline __attribute__((always_inline))

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;
	case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;
	case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;
	case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE and WRITE_ONCE, but only when the compiler is aware of some
 * particular ordering. One way to make the compiler aware of ordering is to
 * put the two invocations of READ_ONCE or WRITE_ONCE in different C
 * statements.
 *
 * These two macros will also work on aggregate data types like structs or
 * unions. If the size of the accessed data type exceeds the word size of
 * the machine (e.g., 32 bits or 64 bits) READ_ONCE() and WRITE_ONCE() will
 * fall back to memcpy and print a compile-time warning.
 *
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */

#define READ_ONCE(x)					\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__c = { 0 } };			\
	__read_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile uint8_t *) p = *(uint8_t  *) res; break;
	case 2: *(volatile uint16_t *) p = *(uint16_t *) res; break;
	case 4: *(volatile uint32_t *) p = *(uint32_t *) res; break;
	case 8: *(volatile uint64_t *) p = *(uint64_t *) res; break;
	default:
		barrier();
		__builtin_memcpy((void *)p, (const void *)res, size);
		barrier();
	}
}

#define WRITE_ONCE(x, val)				\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (val) }; 			\
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#endif /* !__ASSEMBLY__ */
#endif /* !__LINUX_COMPILER_H */
