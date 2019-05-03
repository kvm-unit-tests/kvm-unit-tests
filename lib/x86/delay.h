#ifndef __X86_DELAY__
#define __X86_DELAY__

#include "libcflat.h"

#define IPI_DELAY 1000000

void delay(u64 count);

static inline void io_delay(void)
{
	delay(IPI_DELAY);
}

#endif
