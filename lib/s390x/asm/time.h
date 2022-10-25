/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Clock utilities for s390
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *
 * Copied from the s390/intercept test by:
 *  Pierre Morel <pmorel@linux.ibm.com>
 */
#ifndef _ASMS390X_TIME_H_
#define _ASMS390X_TIME_H_

#define S390_CLOCK_SHIFT_US	(63 - 51)

#define STCK_SHIFT_US	S390_CLOCK_SHIFT_US
#define STCK_MAX	((1UL << 52) - 1)

#define CPU_TIMER_SHIFT_US	S390_CLOCK_SHIFT_US

static inline int sck(uint64_t *time)
{
	int cc;

	asm volatile(
		"	sck %[time]\n"
		"	ipm %[cc]\n"
		"	srl %[cc],28\n"
		: [cc] "=d"(cc)
		: [time] "Q"(*time)
		: "cc"
	);

	return cc;
}

static inline int stck(uint64_t *time)
{
	int cc;

	asm volatile(
		"	stck %[time]\n"
		"	ipm %[cc]\n"
		"	srl %[cc],28\n"
		: [cc] "=d" (cc), [time] "=Q" (*time)
		:
		: "cc"
	);

	return cc;
}

static inline int stckf(uint64_t *time)
{
	int cc;

	asm volatile(
		"	stckf %[time]\n"
		"	ipm %[cc]\n"
		"	srl %[cc],28\n"
		: [cc] "=d" (cc), [time] "=Q" (*time)
		:
		: "cc"
	);

	return cc;
}

static inline uint64_t get_clock_us(void)
{
	uint64_t clk;

	stck(&clk);

	return clk >> STCK_SHIFT_US;
}

static inline uint64_t get_clock_ms(void)
{
	return get_clock_us() / 1000;
}

static inline void udelay(unsigned long us)
{
	unsigned long startclk = get_clock_us();
	unsigned long c;

	do {
		c = get_clock_us();
		if (c < startclk)
			c += STCK_MAX;
	} while (c < startclk + us);
}

static inline void mdelay(unsigned long ms)
{
	udelay(ms * 1000);
}

static inline void cpu_timer_set_ms(int64_t timeout_ms)
{
	int64_t timer_value = (timeout_ms * 1000) << CPU_TIMER_SHIFT_US;

	asm volatile (
		"spt %[timer_value]\n"
		:
		: [timer_value] "Q" (timer_value)
	);
}

#endif
