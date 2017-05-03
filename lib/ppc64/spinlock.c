/*
 * ppc64 (dummy) spinlock implementation
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include <asm/spinlock.h>

void spin_lock(struct spinlock *lock)
{
        lock->v = 1;
}

void spin_unlock(struct spinlock *lock)
{
        lock->v = 0;
}
