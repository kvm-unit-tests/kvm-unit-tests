#ifndef _ASMPOWERPC_TIME_H_
#define _ASMPOWERPC_TIME_H_

#include <libcflat.h>
#include <asm/processor.h>
#include <asm/reg.h>

static inline uint64_t get_tb(void)
{
	return mfspr(SPR_TB);
}

extern uint64_t get_clock_us(void);
extern uint64_t get_clock_ms(void);
extern void delay(uint64_t cycles);
extern void udelay(uint64_t us);
extern void sleep_tb(uint64_t cycles);
extern void usleep(uint64_t us);

static inline void mdelay(uint64_t ms)
{
	while (ms--)
		udelay(1000);
}

static inline void msleep(uint64_t ms)
{
	usleep(ms * 1000);
}

#endif /* _ASMPOWERPC_TIME_H_ */
