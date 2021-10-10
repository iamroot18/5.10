/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MCS lock defines
 *
 * This file contains the main data structure and API definitions of MCS lock.
 *
 * The MCS lock (proposed by Mellor-Crummey and Scott) is a simple spin-lock
 * with the desirable properties of being fair, and with each cpu trying
 * to acquire the lock spinning on a local variable.
 * It avoids expensive cache bouncings that common test-and-set spin-lock
 * implementations incur.
 */
#ifndef __LINUX_MCS_SPINLOCK_H
#define __LINUX_MCS_SPINLOCK_H

#include <asm/mcs_spinlock.h>

/*
 * IAMROOT, 2021.10.09:
 *
 * qspinlock 구현에 사용되는 mcs 노드에 대한 구조체이다.
 * locked: 1=lock, 0=unlock.
 *  count: nest count (최대 4).
 */
struct mcs_spinlock {
	struct mcs_spinlock *next;
	int locked; /* 1 if lock acquired */
	int count;  /* nesting count, see qspinlock.c */
};

/*
 * IAMROOT, 2021.10.09:
 *
 * - contended queue 에서 uncontended queue 상태로 가기 위한 매크로.
 *
 * - spin-waiting:
 *     l값이 0(=unlock)이면 sleep하고
 *     l값이 변화할때마다 깨어나서 l값을 다시 확인.
 *     l값이 1(=lock)이 되면 return한다.
 *
 * - 실제 쓰이는 코드의 문맥에서 생각해보면,
 *   uncontended queue 에 있는 MCS node가 uncontended 상태로 가기 전에
 *   next에 있는 MCS node의 locked값을 1로 만들어 주게 되고,
 *   (아래의 arch_mcs_spin_unlock_contended 참조)
 *   next에 있는 MCS node는 uncontended queue 상태로 넘어가게 된다.
 *
 * - 단방향 베리어 적용 (acquire).
 */
#ifndef arch_mcs_spin_lock_contended
/*
 * Using smp_cond_load_acquire() provides the acquire semantics
 * required so that subsequent operations happen after the
 * lock is acquired. Additionally, some architectures such as
 * ARM64 would like to do spin-waiting instead of purely
 * spinning, and smp_cond_load_acquire() provides that behavior.
 */
#define arch_mcs_spin_lock_contended(l)					\
do {									\
	smp_cond_load_acquire(l, VAL);					\
} while (0)
#endif

/*
 * IAMROOT, 2021.10.09:
 *
 * - target MCS node의 상태를 contended queue에서 uncontended queue 상태로 만들기 위한 매크로.
 *
 * - target MCS node의 locked 값을 1로 바꾸어 준다.
 *
 * - arch_mcs_spin_lock_contended와 연관 지어 생각해 보면
 *   왜 함수의 이름이 unlock이고 release인지 알 수 있다.
 *
 * - 단방향 베리어 적용 (release).
 */
#ifndef arch_mcs_spin_unlock_contended
/*
 * smp_store_release() provides a memory barrier to ensure all
 * operations in the critical section has been completed before
 * unlocking.
 */
#define arch_mcs_spin_unlock_contended(l)				\
	smp_store_release((l), 1)
#endif

/*
 * Note: the smp_load_acquire/smp_store_release pair is not
 * sufficient to form a full memory barrier across
 * cpus for many architectures (except x86) for mcs_unlock and mcs_lock.
 * For applications that need a full barrier across multiple cpus
 * with mcs_unlock and mcs_lock pair, smp_mb__after_unlock_lock() should be
 * used after mcs_lock.
 */

/*
 * In order to acquire the lock, the caller should declare a local node and
 * pass a reference of the node to this function in addition to the lock.
 * If the lock has already been acquired, then this will proceed to spin
 * on this node->locked until the previous lock holder sets the node->locked
 * in mcs_spin_unlock().
 */
static inline
void mcs_spin_lock(struct mcs_spinlock **lock, struct mcs_spinlock *node)
{
	struct mcs_spinlock *prev;

	/* Init node */
	node->locked = 0;
	node->next   = NULL;

	/*
	 * We rely on the full barrier with global transitivity implied by the
	 * below xchg() to order the initialization stores above against any
	 * observation of @node. And to provide the ACQUIRE ordering associated
	 * with a LOCK primitive.
	 */
	prev = xchg(lock, node);
	if (likely(prev == NULL)) {
		/*
		 * Lock acquired, don't need to set node->locked to 1. Threads
		 * only spin on its own node->locked value for lock acquisition.
		 * However, since this thread can immediately acquire the lock
		 * and does not proceed to spin on its own node->locked, this
		 * value won't be used. If a debug mode is needed to
		 * audit lock status, then set node->locked value here.
		 */
		return;
	}
	WRITE_ONCE(prev->next, node);

	/* Wait until the lock holder passes the lock down. */
	arch_mcs_spin_lock_contended(&node->locked);
}

/*
 * Releases the lock. The caller should pass in the corresponding node that
 * was used to acquire the lock.
 */
static inline
void mcs_spin_unlock(struct mcs_spinlock **lock, struct mcs_spinlock *node)
{
	struct mcs_spinlock *next = READ_ONCE(node->next);

	if (likely(!next)) {
		/*
		 * Release the lock by setting it to NULL
		 */
		if (likely(cmpxchg_release(lock, node, NULL) == node))
			return;
		/* Wait until the next pointer is set */
		while (!(next = READ_ONCE(node->next)))
			cpu_relax();
	}

	/* Pass lock to next waiter. */
	arch_mcs_spin_unlock_contended(&next->locked);
}

#endif /* __LINUX_MCS_SPINLOCK_H */
