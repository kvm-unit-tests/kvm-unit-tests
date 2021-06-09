#ifndef _X86_DELAY_H_
#define _X86_DELAY_H_

#include "libcflat.h"

#define IPI_DELAY 1000000

void delay(u64 count);

static inline void io_delay(void)
{
	delay(IPI_DELAY);
}

#endif
