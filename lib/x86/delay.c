#include "delay.h"
#include "processor.h"

void delay(u64 count)
{
	u64 start = rdtsc();

	do {
		pause();
	} while (rdtsc() - start < count);
}
