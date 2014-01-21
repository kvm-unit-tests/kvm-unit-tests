#ifndef _ASMARM_SPINLOCK_H_
#define _ASMARM_SPINLOCK_H_

struct spinlock {
	int v;
};

//TODO
static inline void spin_lock(struct spinlock *lock __unused)
{
}
static inline void spin_unlock(struct spinlock *lock __unused)
{
}

#endif /* _ASMARM_SPINLOCK_H_ */
