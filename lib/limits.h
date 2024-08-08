/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LIMITS_H_
#define _LIMITS_H_

#if __CHAR_BIT__ == 8
# if __CHAR_UNSIGNED__
#  define CHAR_MIN	0
#  define CHAR_MAX	__UINT8_MAX__
# else
#  define CHAR_MAX	__INT8_MAX__
#  define CHAR_MIN	(-CHAR_MAX - 1)
# endif
#endif

#if __SHRT_WIDTH__ == 16
# define SHRT_MAX	__INT16_MAX__
# define SHRT_MIN	(-SHRT_MAX - 1)
# define USHRT_MAX	__UINT16_MAX__
#endif

#if __INT_WIDTH__ == 32
# define INT_MAX	__INT32_MAX__
# define INT_MIN	(-INT_MAX - 1)
# define UINT_MAX	__UINT32_MAX__
#endif

#if __LONG_WIDTH__ == 64
# define LONG_MAX	__INT64_MAX__
# define LONG_MIN	(-LONG_MAX - 1)
# define ULONG_MAX	__UINT64_MAX__
#elif __LONG_WIDTH__ == 32
# define LONG_MAX	__INT32_MAX__
# define LONG_MIN	(-LONG_MAX - 1)
# define ULONG_MAX	__UINT32_MAX__
#endif

#if __LONG_LONG_WIDTH__ == 64
# define LLONG_MAX	__INT64_MAX__
# define LLONG_MIN	(-LLONG_MAX - 1)
# define ULLONG_MAX	__UINT64_MAX__
#endif

#endif /* _LIMITS_H_ */
