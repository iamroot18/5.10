/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Queued spinlock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 * (C) Copyright 2015 Hewlett-Packard Enterprise Development LP
 *
 * Authors: Waiman Long <waiman.long@hpe.com>
 */
#ifndef __ASM_GENERIC_QSPINLOCK_H
#define __ASM_GENERIC_QSPINLOCK_H

#include <asm-generic/qspinlock_types.h>
#include <linux/atomic.h>

#ifndef queued_spin_is_locked
/**
 * queued_spin_is_locked - is the spinlock locked?
 * @lock: Pointer to queued spinlock structure
 * Return: 1 if it is locked, 0 otherwise
 */
static __always_inline int queued_spin_is_locked(struct qspinlock *lock)
{
	/*
	 * Any !0 state indicates it is locked, even if _Q_LOCKED_VAL
	 * isn't immediately observable.
	 */
	return atomic_read(&lock->val);
}
#endif

/**
 * queued_spin_value_unlocked - is the spinlock structure unlocked?
 * @lock: queued spinlock structure
 * Return: 1 if it is unlocked, 0 otherwise
 *
 * N.B. Whenever there are tasks waiting for the lock, it is considered
 *      locked wrt the lockref code to avoid lock stealing by the lockref
 *      code and change things underneath the lock. This also allows some
 *      optimizations to be applied without conflict with lockref.
 */
static __always_inline int queued_spin_value_unlocked(struct qspinlock lock)
{
	return !atomic_read(&lock.val);
}

/**
 * queued_spin_is_contended - check if the lock is contended
 * @lock : Pointer to queued spinlock structure
 * Return: 1 if lock contended, 0 otherwise
 */
static __always_inline int queued_spin_is_contended(struct qspinlock *lock)
{
	return atomic_read(&lock->val) & ~_Q_LOCKED_MASK;
}
/**
 * queued_spin_trylock - try to acquire the queued spinlock
 * @lock : Pointer to queued spinlock structure
 * Return: 1 if lock acquired, 0 if failed
 */
static __always_inline int queued_spin_trylock(struct qspinlock *lock)
{
	u32 val = atomic_read(&lock->val);

	if (unlikely(val))
		return 0;
/*
 * IAMROOT, 2021.09.25: 
 * - val 값이 0인 경우에만 이 곳으로 온다. 즉 unlock 상태. 
 *
 * - 아래 코드에서는 다른 smp core가 먼저 lock을 획득한 경우 lock->val이 0이 아닌 
 *   값이 저장되며, 이 때 lock 획득이 실패한다.
 *   여전히 lock->val이 0인 상태인 경우에만 1로 교체 시도하여 성공하면 
 *   lock을 획득하게 된다.
 */
	return likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL));
}

extern void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);

/*
 * IAMROOT, 2021.09.25: 
 * - 무조건 lock을 획득하는데 누군가 먼저 lock을 획득한 상태라면,
 *   내 차례가 와서 lock을 획득할 때 까지 무한 spin 한다.
 *
 * - 무조건 성공이므로 void 반환을 사용한다.
 */
#ifndef queued_spin_lock
/**
 * queued_spin_lock - acquire a queued spinlock
 * @lock: Pointer to queued spinlock structure
 */
static __always_inline void queued_spin_lock(struct qspinlock *lock)
{
	u32 val = 0;

/* IAMROOT, 2021.09.25: fast-path
 * - val = 0 으로 비교하는 이유
 *   spin_lock_init에서 val을 0으로 초기화 시킨다. 그러므로 old값이
 *   spin_lock_init에서 초기화한 0일 것이고, 해당 old값인 0으로 비교하는것이다.
 */
	if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL)))
		return;
/* IAMROOT, 2021.09.25: slow-path
 * - lock은 풀렸으나 pending/tail bits가 set되어도 fast-path 실패로 간주하는데
 *   pending cpu가 다음 lock-owner가 되어야 하기 때문이다.
 *
 * - fast-path 성공/실패 케이스
 *   성공 (반환 1): val == (0,0,0)
 *   실패 (반환 0): val != (0,0,0) 따라서 (*,*,1) / (*,1,*) / (n,*,*) 이다.
 *
 *   예) (*,1,0) 라면 lock-owner는 없으나 spinning cpus >= 1인 경우이다.
 */
	queued_spin_lock_slowpath(lock, val);
}
#endif

#ifndef queued_spin_unlock
/*
 * IAMROOT, 2021.10.02:
 * - release를 사용해 lock할때 걸었던 acquire를 풀어준다.
 *
 * - smp_store_release를 사용할때 wfe도 같이 풀린다.
 */
/**
 * queued_spin_unlock - release a queued spinlock
 * @lock : Pointer to queued spinlock structure
 */
static __always_inline void queued_spin_unlock(struct qspinlock *lock)
{
	/*
	 * unlock() needs release semantics:
	 */
	smp_store_release(&lock->locked, 0);
}
#endif

#ifndef virt_spin_lock
static __always_inline bool virt_spin_lock(struct qspinlock *lock)
{
	return false;
}
#endif

/*
 * Remapping spinlock architecture specific functions to the corresponding
 * queued spinlock functions.
 */
#define arch_spin_is_locked(l)		queued_spin_is_locked(l)
#define arch_spin_is_contended(l)	queued_spin_is_contended(l)
#define arch_spin_value_unlocked(l)	queued_spin_value_unlocked(l)
#define arch_spin_lock(l)		queued_spin_lock(l)
#define arch_spin_trylock(l)		queued_spin_trylock(l)
#define arch_spin_unlock(l)		queued_spin_unlock(l)

#endif /* __ASM_GENERIC_QSPINLOCK_H */
