#ifndef __LINUX_SPINLOCK_API_UP_H
#define __LINUX_SPINLOCK_API_UP_H

#ifndef __LINUX_SPINLOCK_H
# error "please don't include this file directly"
#endif

/*
 * include/linux/spinlock_api_up.h
 *
 * spinlock API implementation on UP-nondebug (inlined implementation)
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#define in_lock_functions(ADDR)		0

#define assert_raw_spin_locked(lock)	do { (void)(lock); } while (0)
/*
 * IAMROOT, 2021.10.01:
 * - 제일 간단한 케이스로, UP의 경우 task 변경만 안되면 일반적인 상황에서
 *   다른 lock을 할 필요없다. 예를 들어
 *   A task에서 lock을 건상태에서 B task 를 실행되고 해당 lock을 또 얻을경우
 *   이걸 풀 방법이 없다. 다른 말로는 다른 task로의 이동만 안하면 이러한
 *   일이 발생하지 않는다. 따라서 preempt_disable로 다른 task로의 선점을
 *   막게 함으로 이를 예방한다.
 * - task 경우와는 다르게 irq가 발생하고 해당 irq 루틴에서 lock을 얻어버리면
 *   또 데드락이 발생해버린다. 그래서 irq내에서 해당 lock을 사용해야될경우
 *   __LOCK_IRQ를 사용해서 irq를 막아버린다. bh도 비슷한경우이다.
 */
/*
 * In the UP-nondebug case there's no real locking going on, so the
 * only thing we have to do is to keep the preempt counts and irq
 * flags straight, to suppress compiler warnings of unused lock
 * variables, and to add the proper checker annotations:
 */
#define ___LOCK(lock) \
  do { __acquire(lock); (void)(lock); } while (0)

#define __LOCK(lock) \
  do { preempt_disable(); ___LOCK(lock); } while (0)

#define __LOCK_BH(lock) \
  do { __local_bh_disable_ip(_THIS_IP_, SOFTIRQ_LOCK_OFFSET); ___LOCK(lock); } while (0)

#define __LOCK_IRQ(lock) \
  do { local_irq_disable(); __LOCK(lock); } while (0)

#define __LOCK_IRQSAVE(lock, flags) \
  do { local_irq_save(flags); __LOCK(lock); } while (0)

#define ___UNLOCK(lock) \
  do { __release(lock); (void)(lock); } while (0)

#define __UNLOCK(lock) \
  do { preempt_enable(); ___UNLOCK(lock); } while (0)

#define __UNLOCK_BH(lock) \
  do { __local_bh_enable_ip(_THIS_IP_, SOFTIRQ_LOCK_OFFSET); \
       ___UNLOCK(lock); } while (0)

#define __UNLOCK_IRQ(lock) \
  do { local_irq_enable(); __UNLOCK(lock); } while (0)

#define __UNLOCK_IRQRESTORE(lock, flags) \
  do { local_irq_restore(flags); __UNLOCK(lock); } while (0)

/*
 * IAMROOT, 2021.09.25: 
 * 1) UP 방식: 
 *   -> _raw_spin_lock()
 *      -> __LOCK()     : preempt_disable()만 사용하는 것으로 spin_lock 구현
 *         -> ___LOCK() : lockdep 추적 코드
 */
#define _raw_spin_lock(lock)			__LOCK(lock)
#define _raw_spin_lock_nested(lock, subclass)	__LOCK(lock)
#define _raw_read_lock(lock)			__LOCK(lock)
#define _raw_write_lock(lock)			__LOCK(lock)
#define _raw_spin_lock_bh(lock)			__LOCK_BH(lock)
#define _raw_read_lock_bh(lock)			__LOCK_BH(lock)
#define _raw_write_lock_bh(lock)		__LOCK_BH(lock)
#define _raw_spin_lock_irq(lock)		__LOCK_IRQ(lock)
#define _raw_read_lock_irq(lock)		__LOCK_IRQ(lock)
#define _raw_write_lock_irq(lock)		__LOCK_IRQ(lock)
#define _raw_spin_lock_irqsave(lock, flags)	__LOCK_IRQSAVE(lock, flags)
#define _raw_read_lock_irqsave(lock, flags)	__LOCK_IRQSAVE(lock, flags)
#define _raw_write_lock_irqsave(lock, flags)	__LOCK_IRQSAVE(lock, flags)
#define _raw_spin_trylock(lock)			({ __LOCK(lock); 1; })
#define _raw_read_trylock(lock)			({ __LOCK(lock); 1; })
#define _raw_write_trylock(lock)			({ __LOCK(lock); 1; })
#define _raw_spin_trylock_bh(lock)		({ __LOCK_BH(lock); 1; })
#define _raw_spin_unlock(lock)			__UNLOCK(lock)
#define _raw_read_unlock(lock)			__UNLOCK(lock)
#define _raw_write_unlock(lock)			__UNLOCK(lock)
#define _raw_spin_unlock_bh(lock)		__UNLOCK_BH(lock)
#define _raw_write_unlock_bh(lock)		__UNLOCK_BH(lock)
#define _raw_read_unlock_bh(lock)		__UNLOCK_BH(lock)
#define _raw_spin_unlock_irq(lock)		__UNLOCK_IRQ(lock)
#define _raw_read_unlock_irq(lock)		__UNLOCK_IRQ(lock)
#define _raw_write_unlock_irq(lock)		__UNLOCK_IRQ(lock)
#define _raw_spin_unlock_irqrestore(lock, flags) \
					__UNLOCK_IRQRESTORE(lock, flags)
#define _raw_read_unlock_irqrestore(lock, flags) \
					__UNLOCK_IRQRESTORE(lock, flags)
#define _raw_write_unlock_irqrestore(lock, flags) \
					__UNLOCK_IRQRESTORE(lock, flags)

#endif /* __LINUX_SPINLOCK_API_UP_H */
