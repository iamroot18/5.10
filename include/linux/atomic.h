/* SPDX-License-Identifier: GPL-2.0 */
/* Atomic operations usable in machine independent code */
#ifndef _LINUX_ATOMIC_H
#define _LINUX_ATOMIC_H
#include <linux/types.h>
/*
 * IAMROOT, 2021.09.18:
 * - atomic 함수의 추척
 * atomic_add - include/asm-generic/atomic-instrumented.h
 * arch_atomic_add -> arch/arm64/include/asm/atomic.h
 *  __lse_ll_sc_body(atomic_add, ..) -> arch/arm64/include/asm/lse.h  
 *    __ll_sc__atomic_add -> arch/arm64/include/asm/atomic_ll_sc.h
 *    __lse_atomic_add    -> arch/arm64/include/asm/atomic_lse.h
 *
 * atomic_xchg - include/asm-generic/atomic-instrumented.h
 * arch_atomic_xchg -> arch/arm64/include/asm/atomic.h
 *  arch_xchg -> arch/arm64/include/asm/cmpxchg.h
 *    __xchg_wrapper( _mb, ...) -> (같은파일)
 *    __xchg_mb -> (같은파일)
 *    __xchg_case_mb_32 -> (같은파일)
 *
 * atomic_cmpxchg - include/asm-generic/atomic-instrumented.h
 * arch_atomic_cmpxchg ->  arch/arm64/include/asm/atomic.h
 *  arch_cmpxchg -> arch/arm64/include/asm/cmpxchg.h
 *    __cmpxchg_wrapper( _mb, ...) -> (같은파일)
 *    __cmpxchg_mb -> (같은파일)
 *    __cmpxchg_case_mb_32 -> (같은파일)
 *    __lse_ll_sc_body(_cmpxchg_case_mb_32, ...) -> (같은파일)
 *      __ll_sc__cmpxchg_case_mb_32 -> arch/arm64/include/asm/atomic_ll_sc.h
 *      __lse__cmpxchg_case_mb_32 -> arch/arm64/include/asm/atomic_lse.h
 */
 
#include <asm/atomic.h>
#include <asm/barrier.h>

/*
 * Relaxed variants of xchg, cmpxchg and some atomic operations.
 *
 * We support four variants:
 *
 * - Fully ordered: The default implementation, no suffix required.
 * - Acquire: Provides ACQUIRE semantics, _acquire suffix.
 * - Release: Provides RELEASE semantics, _release suffix.
 * - Relaxed: No ordering guarantees, _relaxed suffix.
 *
 * For compound atomics performing both a load and a store, ACQUIRE
 * semantics apply only to the load and RELEASE semantics only to the
 * store portion of the operation. Note that a failed cmpxchg_acquire
 * does -not- imply any memory ordering constraints.
 *
 * See Documentation/memory-barriers.txt for ACQUIRE/RELEASE definitions.
 */

#define atomic_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))

#define atomic64_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))

/*
 * The idea here is to build acquire/release variants by adding explicit
 * barriers on top of the relaxed variant. In the case where the relaxed
 * variant is already fully ordered, no additional barriers are needed.
 *
 * If an architecture overrides __atomic_acquire_fence() it will probably
 * want to define smp_mb__after_spinlock().
 */
#ifndef __atomic_acquire_fence
#define __atomic_acquire_fence		smp_mb__after_atomic
#endif

#ifndef __atomic_release_fence
#define __atomic_release_fence		smp_mb__before_atomic
#endif

#ifndef __atomic_pre_full_fence
#define __atomic_pre_full_fence		smp_mb__before_atomic
#endif

#ifndef __atomic_post_full_fence
#define __atomic_post_full_fence	smp_mb__after_atomic
#endif

#define __atomic_op_acquire(op, args...)				\
({									\
	typeof(op##_relaxed(args)) __ret  = op##_relaxed(args);		\
	__atomic_acquire_fence();					\
	__ret;								\
})

#define __atomic_op_release(op, args...)				\
({									\
	__atomic_release_fence();					\
	op##_relaxed(args);						\
})

#define __atomic_op_fence(op, args...)					\
({									\
	typeof(op##_relaxed(args)) __ret;				\
	__atomic_pre_full_fence();					\
	__ret = op##_relaxed(args);					\
	__atomic_post_full_fence();					\
	__ret;								\
})

#ifdef ARCH_ATOMIC
#include <linux/atomic-arch-fallback.h>
#include <asm-generic/atomic-instrumented.h>
#else
#include <linux/atomic-fallback.h>
#endif

#include <asm-generic/atomic-long.h>

#endif /* _LINUX_ATOMIC_H */
