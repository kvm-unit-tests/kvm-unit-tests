#ifndef _ASMARM64_SPINLOCK_H_
#define _ASMARM64_SPINLOCK_H_

struct spinlock {
	int v;
};

static inline void spin_lock(struct spinlock *lock __unused)
{
}
static inline void spin_unlock(struct spinlock *lock __unused)
{
}

#endif /* _ASMARM64_SPINLOCK_H_ */
