#include "libcflat.h"
#include "asm/spinlock.h"
#include "asm/barrier.h"

void spin_lock(struct spinlock *lock)
{
	u32 val, fail;

	dmb();
	do {
		asm volatile(
		"1:	ldrex	%0, [%2]\n"
		"	teq	%0, #0\n"
		"	bne	1b\n"
		"	mov	%0, #1\n"
		"	strex	%1, %0, [%2]\n"
		: "=&r" (val), "=&r" (fail)
		: "r" (&lock->v)
		: "cc" );
	} while (fail);
	dmb();
}

void spin_unlock(struct spinlock *lock)
{
	lock->v = 0;
	dmb();
}
