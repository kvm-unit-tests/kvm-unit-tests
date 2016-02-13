#include <asm/spinlock.h>

void spin_lock(struct spinlock *lock)
{
        lock->v = 1;
}

void spin_unlock(struct spinlock *lock)
{
        lock->v = 0;
}
