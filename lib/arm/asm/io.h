#ifndef _ASMARM_IO_H_
#define _ASMARM_IO_H_
#include "libcflat.h"
#include "asm/barrier.h"

#define __bswap16 bswap16
static inline u16 bswap16(u16 val)
{
	u16 ret;
	asm volatile("rev16 %0, %1" : "=r" (ret) :  "r" (val));
	return ret;
}

#define __bswap32 bswap32
static inline u32 bswap32(u32 val)
{
	u32 ret;
	asm volatile("rev %0, %1" : "=r" (ret) :  "r" (val));
	return ret;
}

#include "asm-generic/io.h"

#endif /* _ASMARM_IO_H_ */
