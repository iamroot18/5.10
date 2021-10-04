// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Queued spinlock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 * (C) Copyright 2013-2014,2018 Red Hat, Inc.
 * (C) Copyright 2015 Intel Corp.
 * (C) Copyright 2015 Hewlett-Packard Enterprise Development LP
 *
 * Authors: Waiman Long <longman@redhat.com>
 *          Peter Zijlstra <peterz@infradead.org>
 */

#ifndef _GEN_PV_LOCK_SLOWPATH

#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>
#include <linux/prefetch.h>
#include <asm/byteorder.h>
#include <asm/qspinlock.h>

/*
 * Include queued spinlock statistics code
 */
#include "qspinlock_stat.h"

/*
 * The basic principle of a queue-based spinlock can best be understood
 * by studying a classic queue-based spinlock implementation called the
 * MCS lock. A copy of the original MCS lock paper ("Algorithms for Scalable
 * Synchronization on Shared-Memory Multiprocessors by Mellor-Crummey and
 * Scott") is available at
 *
 * https://bugzilla.kernel.org/show_bug.cgi?id=206115
 *
 * This queued spinlock implementation is based on the MCS lock, however to
 * make it fit the 4 bytes we assume spinlock_t to be, and preserve its
 * existing API, we must modify it somehow.
 *
 * In particular; where the traditional MCS lock consists of a tail pointer
 * (8 bytes) and needs the next pointer (another 8 bytes) of its own node to
 * unlock the next pending (next->locked), we compress both these: {tail,
 * next->locked} into a single u32 value.
 *
 * Since a spinlock disables recursion of its own context and there is a limit
 * to the contexts that can nest; namely: task, softirq, hardirq, nmi. As there
 * are at most 4 nesting levels, it can be encoded by a 2-bit number. Now
 * we can encode the tail by combining the 2-bit nesting level with the cpu
 * number. With one byte for the lock value and 3 bytes for the tail, only a
 * 32-bit word is now needed. Even though we only need 1 bit for the lock,
 * we extend it to a full byte to achieve better performance for architectures
 * that support atomic byte write.
 *
 * We also change the first spinner to spin on the lock bit instead of its
 * node; whereby avoiding the need to carry a node from lock to unlock, and
 * preserving existing lock API. This also makes the unlock code simpler and
 * faster.
 *
 * N.B. The current implementation only supports architectures that allow
 *      atomic operations on smaller 8-bit and 16-bit data types.
 *
 */

#include "mcs_spinlock.h"

/*
 * IAMROOT, 2021.09.25: cpu당 최대 nest 가능한 수
 */
#define MAX_NODES	4

/*
 * On 64-bit architectures, the mcs_spinlock structure will be 16 bytes in
 * size and four of them will fit nicely in one 64-byte cacheline. For
 * pvqspinlock, however, we need more space for extra data. To accommodate
 * that, we insert two more long words to pad it up to 32 bytes. IOW, only
 * two of them can fit in a cacheline in this case. That is OK as it is rare
 * to have more than 2 levels of slowpath nesting in actual use. We don't
 * want to penalize pvqspinlocks to optimize for a rare case in native
 * qspinlocks.
 */
struct qnode {
	struct mcs_spinlock mcs;
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	long reserved[2];
#endif
};

/*
 * The pending bit spinning loop count.
 * This heuristic is used to limit the number of lockword accesses
 * made by atomic_cond_read_relaxed when waiting for the lock to
 * transition out of the "== _Q_PENDING_VAL" state. We don't spin
 * indefinitely because there's no guarantee that we'll make forward
 * progress.
 */
#ifndef _Q_PENDING_LOOPS
#define _Q_PENDING_LOOPS	1
#endif

/*
 * Per-CPU queue node structures; we can never have more than 4 nested
 * contexts: task, softirq, hardirq, nmi.
 *
 * Exactly fits one 64-byte cacheline on a 64-bit architecture.
 *
 * PV doubles the storage and uses the second cacheline for PV state.
 */

/*
 * IAMROOT, 2021.09.25: 
 * - mcs queue node는 cpu별로 최대 4개씩 구성된다.
 */
static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[MAX_NODES]);
/*
 * IAMROOT, 2021.10.02:
 * - tail에 set되는 cpu는 1씩 증가한 상태로 쓴다(0은 no tail의 의미로
 *   쓰기때문)
 */
/*
 * We must be able to distinguish between no-tail and the tail at 0:0,
 * therefore increment the cpu number by one.
 */

static inline __pure u32 encode_tail(int cpu, int idx)
{
	u32 tail;

	tail  = (cpu + 1) << _Q_TAIL_CPU_OFFSET;
	tail |= idx << _Q_TAIL_IDX_OFFSET; /* assume < 4 */

	return tail;
}

static inline __pure struct mcs_spinlock *decode_tail(u32 tail)
{
	int cpu = (tail >> _Q_TAIL_CPU_OFFSET) - 1;
	int idx = (tail &  _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;

	return per_cpu_ptr(&qnodes[idx].mcs, cpu);
}

static inline __pure
struct mcs_spinlock *grab_mcs_node(struct mcs_spinlock *base, int idx)
{
	return &((struct qnode *)base + idx)->mcs;
}

#define _Q_LOCKED_PENDING_MASK (_Q_LOCKED_MASK | _Q_PENDING_MASK)

#if _Q_PENDING_BITS == 8
/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
static __always_inline void clear_pending(struct qspinlock *lock)
{
	WRITE_ONCE(lock->pending, 0);
}
/*
 * IAMROOT, 2021.10.02:
 * - pending을 clear하면서 lock을 변경한다.
 *   두 변수를 동시에 set하기위해 union으로 만들어 놨던
 *   locked_pending을 사용한것이 보인다.
 */
/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 *
 * Lock stealing is not allowed if this function is used.
 */
static __always_inline void clear_pending_set_locked(struct qspinlock *lock)
{
	WRITE_ONCE(lock->locked_pending, _Q_LOCKED_VAL);
}

/*
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail), which heads an address dependency
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
static __always_inline u32 xchg_tail(struct qspinlock *lock, u32 tail)
{
	/*
	 * We can use relaxed semantics since the caller ensures that the
	 * MCS node is properly initialized before updating the tail.
	 */
	return (u32)xchg_relaxed(&lock->tail,
				 tail >> _Q_TAIL_OFFSET) << _Q_TAIL_OFFSET;
}

#else /* _Q_PENDING_BITS == 8 */

/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
static __always_inline void clear_pending(struct qspinlock *lock)
{
	atomic_andnot(_Q_PENDING_VAL, &lock->val);
}

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 */
static __always_inline void clear_pending_set_locked(struct qspinlock *lock)
{
	atomic_add(-_Q_PENDING_VAL + _Q_LOCKED_VAL, &lock->val);
}

/**
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail)
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
static __always_inline u32 xchg_tail(struct qspinlock *lock, u32 tail)
{
	u32 old, new, val = atomic_read(&lock->val);

	for (;;) {
		new = (val & _Q_LOCKED_PENDING_MASK) | tail;
		/*
		 * We can use relaxed semantics since the caller ensures that
		 * the MCS node is properly initialized before updating the
		 * tail.
		 */
		old = atomic_cmpxchg_relaxed(&lock->val, val, new);
		if (old == val)
			break;

		val = old;
	}
	return old;
}
#endif /* _Q_PENDING_BITS == 8 */

/**
 * queued_fetch_set_pending_acquire - fetch the whole lock value and set pending
 * @lock : Pointer to queued spinlock structure
 * Return: The previous lock value
 *
 * *,*,* -> *,1,*
 */
#ifndef queued_fetch_set_pending_acquire
static __always_inline u32 queued_fetch_set_pending_acquire(struct qspinlock *lock)
{
	return atomic_fetch_or_acquire(_Q_PENDING_VAL, &lock->val);
}
#endif

/**
 * set_locked - Set the lock bit and own the lock
 * @lock: Pointer to queued spinlock structure
 *
 * *,*,0 -> *,0,1
 */
static __always_inline void set_locked(struct qspinlock *lock)
{
	WRITE_ONCE(lock->locked, _Q_LOCKED_VAL);
}


/*
 * Generate the native code for queued_spin_unlock_slowpath(); provide NOPs for
 * all the PV callbacks.
 */

static __always_inline void __pv_init_node(struct mcs_spinlock *node) { }
static __always_inline void __pv_wait_node(struct mcs_spinlock *node,
					   struct mcs_spinlock *prev) { }
static __always_inline void __pv_kick_node(struct qspinlock *lock,
					   struct mcs_spinlock *node) { }
static __always_inline u32  __pv_wait_head_or_lock(struct qspinlock *lock,
						   struct mcs_spinlock *node)
						   { return 0; }

#define pv_enabled()		false

#define pv_init_node		__pv_init_node
#define pv_wait_node		__pv_wait_node
#define pv_kick_node		__pv_kick_node
#define pv_wait_head_or_lock	__pv_wait_head_or_lock

#ifdef CONFIG_PARAVIRT_SPINLOCKS
#define queued_spin_lock_slowpath	native_queued_spin_lock_slowpath
#endif

#endif /* _GEN_PV_LOCK_SLOWPATH */

/**
 * queued_spin_lock_slowpath - acquire the queued spinlock
 * @lock: Pointer to queued spinlock structure
 * @val: Current value of the queued spinlock 32-bit word
 *
 * (queue tail, pending bit, lock value)
 *
 *              fast     :    slow                                  :    unlock
 *                       :                                          :
 * uncontended  (0,0,0) -:--> (0,0,1) ------------------------------:--> (*,*,0)
 *                       :       | ^--------.------.             /  :
 *                       :       v           \      \            |  :
 * pending               :    (0,1,1) +--> (0,1,0)   \           |  :
 *                       :       | ^--'              |           |  :
 *                       :       v                   |           |  :
 * uncontended           :    (n,x,y) +--> (n,0,0) --'           |  :
 *   queue               :       | ^--'                          |  :
 *                       :       v                               |  :
 * contended             :    (*,x,y) +--> (*,0,0) ---> (*,0,1) -'  :
 *   queue               :         ^--'                             :
 */

/*
 * IAMROOT, 2021.09.25: 
 * - u8 locked: 
 *	1 비트만 사용한다. (0=no-lock, 1=lock)
 * - u8 pending: 
 *	1 비트만 사용한다. (0=no-pending, 1=pending)
 * - u16: tail(cpu+idx):
 *	14 비트는 cpu, idx에 2비트를 사용.
 *	cpu: 실제 cpu 번호에 +1한 값을 저장한다. (0=no-cpu)
 *	idx: task, bh, irq, nmi 각각으로 변경될 때마다 1씩 증가한다. (defaul: 0)
 *           대부분의 경우 그냥 0을 사용하며, cpu에서 4가지 상태로 관리한다.
 *		예) task(0) -> irq(1)
 *		    task(0) -> irq(1) -> nmi(2)
 *
 * uncontended:
 *	lock 경합없이 lock을 획득할 수 있는 상태. (처음 진입한 cpu)
 * pending:
 *	먼저 진입한 cpu가 lock owner이고, 두 번째로 진입한 cpu인 경우 가볍게 대기.
 * uncontended queue:
 *	세 번째로 진입한 cpu가 queue의 head에서 대기하는 상태로,
 *      큐 내에서 간섭없이 대기중
 * contended queue:
 *      큐 내에서 차순위 이상 대기중인 cpu들이다.
 */
void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	struct mcs_spinlock *prev, *next, *node;
	u32 old, tail;
	int idx;

	BUILD_BUG_ON(CONFIG_NR_CPUS >= (1U << _Q_TAIL_CPU_BITS));

	if (pv_enabled())
		goto pv_queue;

	if (virt_spin_lock(lock))
		return;
	/*
	 * Wait for in-progress pending->locked hand-overs with a bounded
	 * number of spins so that we guarantee forward progress.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	if (val == _Q_PENDING_VAL) {
/*
 * IAMROOT, 2021.10.02:
 * - fast-path일때는 LOCKED이 되어있었지만 막상 여기까지 와보니
 *   그때의 lock은 풀려있고, 2번째 cpu가 pending중인 상태때 진입하는 if문.
 *   2번째 cpu의 pending이 풀리거나 한번만 cpu_relax를 기다린다.
 *
 * - VAL
 *   atomic_cond_read_relaxed 내부에서 쓰는 지역변수. 직접 읽은 값을
 *   비교하기 위한것
 */
/*
 * IAMROOT, 2021.10.04:
 * fast-path 당시 unlock 상태이나 pending cpu가 존재 (0,1,0).
 * (0,1,0)라면 pending cpu가 lock을 획득해야 하니 (0,0,1) 될때까지 대기
 * 하거나 1회 loop하여 기다린다.
 */
		int cnt = _Q_PENDING_LOOPS;
		val = atomic_cond_read_relaxed(&lock->val,
					       (VAL != _Q_PENDING_VAL) || !cnt--);
	}
/*
 * IAMROOT, 2021.10.02:
 * - pending이나 tail에 값이 있다면, 즉 3번째 cpu이상경쟁이 들어 왓을때
 *   queue로 바로 직행한다.
 */
	/*
	 * If we observe any contention; queue.
	 */
	if (val & ~_Q_LOCKED_MASK)
		goto queue;
/*
 * IAMROOT, 2021.10.02:
 * - pending old값이 val에 위치하고 pending을 set 한다.
 */
	/*
	 * trylock || pending
	 *
	 * 0,0,* -> 0,1,* -> 0,0,1 pending, trylock
	 */
	val = queued_fetch_set_pending_acquire(lock);
/*
 * IAMROOT, 2021.10.02:
 * - 만약에 old가 pending이나 tail이 set되있다면, 다른 cpu들이 현재 cpu보다
 *   pending이나 queue로 기다리고 있게 되므로 바로 queue로 직행한다.
 *
 * - fetch_set_pending_acquire 이후 상태
 *   lock->val: (*,1,*)
 *         val: (0,0,*) - 경합이 없는 경우
 *              (n,*,*) - 이미 N cpus 경합한 경우.
 *                        바로 queue로 보낸다.
 */
	/*
	 * If we observe contention, there is a concurrent locker.
	 *
	 * Undo and queue; our setting of PENDING might have made the
	 * n,0,0 -> 0,0,0 transition fail and it will now be waiting
	 * on @next to become !NULL.
	 */
	if (unlikely(val & ~_Q_LOCKED_MASK)) {

		/* Undo PENDING if we set it. */
		if (!(val & _Q_PENDING_MASK))
			clear_pending(lock);

		goto queue;
	}
/*
 * IAMROOT, 2021.10.02:
 * - 현재 cpu(2번째 cpu)는 pending얻은 상태고, 첫번째 cpu가 unlock
 *   될때까지 기다린다.
 */
	/*
	 * We're pending, wait for the owner to go away.
	 *
	 * 0,1,1 -> 0,1,0
	 *
	 * this wait loop must be a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because not all
	 * clear_pending_set_locked() implementations imply full
	 * barriers.
	 */
	if (val & _Q_LOCKED_MASK)
		atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_MASK));
/*
 * IAMROOT, 2021.10.02:
 * - 이때부터 현재 cpu가 lock owner가 된것이다.
 */
	/*
	 * take ownership and clear the pending bit.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	clear_pending_set_locked(lock);
	lockevent_inc(lock_pending);
	return;

	/*
	 * End of pending bit optimistic spinning and beginning of MCS
	 * queuing.
	 */
queue:
	lockevent_inc(lock_slowpath);
pv_queue:
/*
 * IAMROOT, 2021.10.02:
 * - 현재 cpu 번호를 가져와 tail을 set한다.
 */
	node = this_cpu_ptr(&qnodes[0].mcs);
	idx = node->count++;
	tail = encode_tail(smp_processor_id(), idx);
/*
 * IAMROOT, 2021.10.02:
 * - MAX_NODES가 넘는것은 거의 bug라 봐도 무방하지만 예외 처리 차원에서
 *   이렇게 처리해놓은 것으로 보인다.
 */
	/*
	 * 4 nodes are allocated based on the assumption that there will
	 * not be nested NMIs taking spinlocks. That may not be true in
	 * some architectures even though the chance of needing more than
	 * 4 nodes will still be extremely unlikely. When that happens,
	 * we fall back to spinning on the lock directly without using
	 * any MCS node. This is not the most elegant solution, but is
	 * simple enough.
	 */
	if (unlikely(idx >= MAX_NODES)) {
		lockevent_inc(lock_no_node);
		while (!queued_spin_trylock(lock))
			cpu_relax();
		goto release;
	}

	node = grab_mcs_node(node, idx);

	/*
	 * Keep counts of non-zero index values:
	 */
	lockevent_cond_inc(lock_use_node2 + idx - 1, idx);
/*
 * IAMROOT, 2021.10.02:
 * - queue의 마지막에 들어갈 node를 이제 초기화 하는 과정.
 */
	/*
	 * Ensure that we increment the head node->count before initialising
	 * the actual node. If the compiler is kind enough to reorder these
	 * stores, then an IRQ could overwrite our assignments.
	 */
	barrier();

	node->locked = 0;
	node->next = NULL;
	pv_init_node(node);
/*
 * IAMROOT, 2021.10.02:
 * - spin lock의 critical 구간은 굉장히 짧게 쓰기 때문에 lock을 얻을려고
 *   하는 도중에도 풀리는 경우가 다반사이다. 이 경우를 고려한것.
 */
	/*
	 * We touched a (possibly) cold cacheline in the per-cpu queue node;
	 * attempt the trylock once more in the hope someone let go while we
	 * weren't watching.
	 */
	if (queued_spin_trylock(lock))
		goto release;

	/*
	 * Ensure that the initialisation of @node is complete before we
	 * publish the updated tail via xchg_tail() and potentially link
	 * @node into the waitqueue via WRITE_ONCE(prev->next, node) below.
	 */
	smp_wmb();
/*
 * IAMROOT, 2021.10.02:
 * - 만들어 놨던 tail값을 실제 설정하여 queue에 node를 추가한다.
 */
	/*
	 * Publish the updated tail.
	 * We have already touched the queueing cacheline; don't bother with
	 * pending stuff.
	 *
	 * p,*,* -> n,*,*
	 */
	old = xchg_tail(lock, tail);
	next = NULL;
/*
 * IAMROOT, 2021.10.02:
 * - old값 tail이 존재한다는것은 결국 기존에 queue에 대기했던 node가
 *   존재한단 것이고, 해당 node의 next에 현재 node를 가리켜야 되므로
 *   그 과정을 설정하는것.
 */
	/*
	 * if there was a previous node; link it and wait until reaching the
	 * head of the waitqueue.
	 */
	if (old & _Q_TAIL_MASK) {
		prev = decode_tail(old);

		/* Link @node into the waitqueue. */
		WRITE_ONCE(prev->next, node);

		pv_wait_node(node, prev);
/*
 * IAMROOT, 2021.10.02:
 * - 여기에 진입하면 이제 4번째 cpu이상이 라는것이고, 여기서 unlock이
 *   될때까지 기다린다.
 *   또한 여기서 unlock이 됬다는것은 현재 node가 mcs의 선두가 됬다는것이
 *   의미된 상태에서, 현재 cpu 뒤로 또 다른 cpu가 존재하는 경우를
 *   확인해 cache prefetch한다.
 */
		arch_mcs_spin_lock_contended(&node->locked);

		/*
		 * While waiting for the MCS lock, the next pointer may have
		 * been set by another lock waiter. We optimistically load
		 * the next pointer & prefetch the cacheline for writing
		 * to reduce latency in the upcoming MCS unlock operation.
		 */
		next = READ_ONCE(node->next);
		if (next)
			prefetchw(next);
	}
	/*
	 * we're at the head of the waitqueue, wait for the owner & pending to
	 * go away.
	 *
	 * *,x,y -> *,0,0
	 *
	 * this wait loop must use a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because the set_locked() function below
	 * does not imply a full barrier.
	 *
	 * The PV pv_wait_head_or_lock function, if active, will acquire
	 * the lock and return a non-zero value. So we have to skip the
	 * atomic_cond_read_acquire() call. As the next PV queue head hasn't
	 * been designated yet, there is no way for the locked value to become
	 * _Q_SLOW_VAL. So both the set_locked() and the
	 * atomic_cmpxchg_relaxed() calls will be safe.
	 *
	 * If PV isn't active, 0 will be returned instead.
	 *
	 */
	if ((val = pv_wait_head_or_lock(lock, node)))
		goto locked;

/*
 * IAMROOT, 2021.10.02:
 * - 여기까지 왔으면 현재 cpu는 mcs의 첫번째가 되는것이고, 이 앞에 있는
 *   cpu들(lock, peding 중인 cpu들)이 unlock될 때까지 기다리면 된다.
 */
	val = atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_PENDING_MASK));

locked:
	/*
	 * claim the lock:
	 *
	 * n,0,0 -> 0,0,1 : lock, uncontended
	 * *,*,0 -> *,*,1 : lock, contended
	 *
	 * If the queue head is the only one in the queue (lock value == tail)
	 * and nobody is pending, clear the tail code and grab the lock.
	 * Otherwise, we only need to grab the lock.
	 */
/*
 * IAMROOT, 2021.10.02:
 * - 여기까지 왔으면 lock owner가 되야되는것.
 *   mcs에서 혼자 기다리고 있었던 즉, head이면서 tail인 경우를
 *   확인 한다.
 */
	/*
	 * In the PV case we might already have _Q_LOCKED_VAL set, because
	 * of lock stealing; therefore we must also allow:
	 *
	 * n,0,1 -> 0,0,1
	 *
	 * Note: at this point: (val & _Q_PENDING_MASK) == 0, because of the
	 *       above wait condition, therefore any concurrent setting of
	 *       PENDING will make the uncontended transition fail.
	 */
	if ((val & _Q_TAIL_MASK) == tail) {
/*
 * IAMROOT, 2021.10.02:
 * - no contention : mcs에서 혼자 존재하다가 lock을 잡으므로 mcs가
 *   비게 되는 상황. 경쟁자 없이 lock 을 잡고 끝.
 */
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, _Q_LOCKED_VAL))
			goto release; /* No contention */
	}
/*
 * IAMROOT, 2021.10.02:
 * - contention상태. 즉 현재 cpu말고 다른 cpu가 뒤에 더 있는 상태.
 *   (n, 0, 1)로 변경한다.
 */
	/*
	 * Either somebody is queued behind us or _Q_PENDING_VAL got set
	 * which will then detect the remaining tail and queue behind us
	 * ensuring we'll see a @next.
	 */
	set_locked(lock);
/*
 * IAMROOT, 2021.10.02:
 * - 현재는 contention상태인데, 먼저 읽은 next값이 없으면 다시
 *   next를 읽어온다.
 *   어쨋든 이 구간에 왓으면 next가 있어야되는데 cpu 경합 과정에서
 *   next가 잠시 비어있을수도 있는 상황이 있는것처럼 보이며
 *   그 경우 next를 읽을떄까지 기다린다. 이 상황은 매우 짧을것이다.
 */
	/*
	 * contended path; wait for next if not observed yet, release.
	 */
	if (!next)
		next = smp_cond_load_relaxed(&node->next, (VAL));
/*
 * IAMROOT, 2021.10.02:
 * - 자신은 lock owner가 되서 release가 되므로 자신의 다음 cpu를 unlock
 *   해주는것.
 */
	arch_mcs_spin_unlock_contended(&next->locked);
	pv_kick_node(lock, next);

release:
	/*
	 * release the node
	 */
	__this_cpu_dec(qnodes[0].mcs.count);
}
EXPORT_SYMBOL(queued_spin_lock_slowpath);

/*
 * Generate the paravirt code for queued_spin_unlock_slowpath().
 */
#if !defined(_GEN_PV_LOCK_SLOWPATH) && defined(CONFIG_PARAVIRT_SPINLOCKS)
#define _GEN_PV_LOCK_SLOWPATH

#undef  pv_enabled
#define pv_enabled()	true

#undef pv_init_node
#undef pv_wait_node
#undef pv_kick_node
#undef pv_wait_head_or_lock

#undef  queued_spin_lock_slowpath
#define queued_spin_lock_slowpath	__pv_queued_spin_lock_slowpath

#include "qspinlock_paravirt.h"
#include "qspinlock.c"

bool nopvspin __initdata;
static __init int parse_nopvspin(char *arg)
{
	nopvspin = true;
	return 0;
}
early_param("nopvspin", parse_nopvspin);
#endif
