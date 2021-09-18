/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/cmpxchg.h
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_CMPXCHG_H
#define __ASM_CMPXCHG_H

#include <linux/build_bug.h>
#include <linux/compiler.h>

#include <asm/barrier.h>
#include <asm/lse.h>
/*
 * IAMROOT, 2021.09.18:
 * - CONFIG 및 CPU Feature 지원에 따라서 ll_sc, lse둘중 하나를 사용한다.
 *
 * - SWP Xs, Xt, [Xn|SP] : 64bit
 *   SWP{B|H|} Ws, Wt, [Xn|SP] : 8, 16, 32bit
 *   Xt or Wt 값 <- [Xn|SP] (load)
 *   [Xn|SP] <- Xs or Ws 값 (store)
 *   어떤 메모리주소에 있는 값을 읽어오면서 새로운 값을 기록하는데, 이 과정이
 *   atomic으로 이루어진다.
 *
 * - 인자에 따라 다음과 같은 명령어가 만들어진다.
 *   SWP,  SWPA,  SWPL,   SWPAL
 *   SWPB, SWPAB, SWPALB, SWPLB
 *   SWPH, SWPAH, SWPALH, SWPLH
 *
 * - swp의 기능 정리
 *   swp(atomic) + a(acquire) / l(release) / al(acquire + release) / (없음)
 *   + byte(b(1), h(2), 없음(4 or 8))
 *   - ll_sc 일때는 al대신에 dmb를 써야한다.
 * 
 * - __nops 존재 이유 :
 *   alternative를 할려면 code 크기가 똑같아야되는데 lse code는 실제 명령어가
 *   1줄이므로 4줄로 확장하기위에 nop(3)을 넣은것. nop_lse도 마찬가지로
 *   끝에 dmb가 오므로 공백을 넣기 위함이다.
 */
/*
 * We need separate acquire parameters for ll/sc and lse, since the full
 * barrier case is generated as release+dmb for the former and
 * acquire+release for the latter.
 */
#define __XCHG_CASE(w, sfx, name, sz, mb, nop_lse, acq, acq_lse, rel, cl)	\
static inline u##sz __xchg_case_##name##sz(u##sz x, volatile void *ptr)		\
{										\
	u##sz ret;								\
	unsigned long tmp;							\
										\
	asm volatile(ARM64_LSE_ATOMIC_INSN(					\
	/* LL/SC */								\
	"	prfm	pstl1strm, %2\n"					\
	"1:	ld" #acq "xr" #sfx "\t%" #w "0, %2\n"				\
	"	st" #rel "xr" #sfx "\t%w1, %" #w "3, %2\n"			\
	"	cbnz	%w1, 1b\n"						\
	"	" #mb,								\
	/* LSE atomics */							\
	"	swp" #acq_lse #rel #sfx "\t%" #w "3, %" #w "0, %2\n"		\
		__nops(3)							\
	"	" #nop_lse)							\
	: "=&r" (ret), "=&r" (tmp), "+Q" (*(u##sz *)ptr)			\
	: "r" (x)								\
	: cl);									\
										\
	return ret;								\
}

__XCHG_CASE(w, b,     ,  8,        ,    ,  ,  ,  ,         )
__XCHG_CASE(w, h,     , 16,        ,    ,  ,  ,  ,         )
__XCHG_CASE(w,  ,     , 32,        ,    ,  ,  ,  ,         )
__XCHG_CASE( ,  ,     , 64,        ,    ,  ,  ,  ,         )
__XCHG_CASE(w, b, acq_,  8,        ,    , a, a,  , "memory")
__XCHG_CASE(w, h, acq_, 16,        ,    , a, a,  , "memory")
__XCHG_CASE(w,  , acq_, 32,        ,    , a, a,  , "memory")
__XCHG_CASE( ,  , acq_, 64,        ,    , a, a,  , "memory")
__XCHG_CASE(w, b, rel_,  8,        ,    ,  ,  , l, "memory")
__XCHG_CASE(w, h, rel_, 16,        ,    ,  ,  , l, "memory")
__XCHG_CASE(w,  , rel_, 32,        ,    ,  ,  , l, "memory")
__XCHG_CASE( ,  , rel_, 64,        ,    ,  ,  , l, "memory")
__XCHG_CASE(w, b,  mb_,  8, dmb ish, nop,  , a, l, "memory")
__XCHG_CASE(w, h,  mb_, 16, dmb ish, nop,  , a, l, "memory")
__XCHG_CASE(w,  ,  mb_, 32, dmb ish, nop,  , a, l, "memory")
__XCHG_CASE( ,  ,  mb_, 64, dmb ish, nop,  , a, l, "memory")

#undef __XCHG_CASE

#define __XCHG_GEN(sfx)							\
static __always_inline  unsigned long __xchg##sfx(unsigned long x,	\
					volatile void *ptr,		\
					int size)			\
{									\
	switch (size) {							\
	case 1:								\
		return __xchg_case##sfx##_8(x, ptr);			\
	case 2:								\
		return __xchg_case##sfx##_16(x, ptr);			\
	case 4:								\
		return __xchg_case##sfx##_32(x, ptr);			\
	case 8:								\
		return __xchg_case##sfx##_64(x, ptr);			\
	default:							\
		BUILD_BUG();						\
	}								\
									\
	unreachable();							\
}

__XCHG_GEN()
__XCHG_GEN(_acq)
__XCHG_GEN(_rel)
__XCHG_GEN(_mb)

#undef __XCHG_GEN

#define __xchg_wrapper(sfx, ptr, x)					\
({									\
	__typeof__(*(ptr)) __ret;					\
	__ret = (__typeof__(*(ptr)))					\
		__xchg##sfx((unsigned long)(x), (ptr), sizeof(*(ptr))); \
	__ret;								\
})

/* xchg */
#define arch_xchg_relaxed(...)	__xchg_wrapper(    , __VA_ARGS__)
#define arch_xchg_acquire(...)	__xchg_wrapper(_acq, __VA_ARGS__)
#define arch_xchg_release(...)	__xchg_wrapper(_rel, __VA_ARGS__)
#define arch_xchg(...)		__xchg_wrapper( _mb, __VA_ARGS__)

#define __CMPXCHG_CASE(name, sz)			\
static inline u##sz __cmpxchg_case_##name##sz(volatile void *ptr,	\
					      u##sz old,		\
					      u##sz new)		\
{									\
	return __lse_ll_sc_body(_cmpxchg_case_##name##sz,		\
				ptr, old, new);				\
}

__CMPXCHG_CASE(    ,  8)
__CMPXCHG_CASE(    , 16)
__CMPXCHG_CASE(    , 32)
__CMPXCHG_CASE(    , 64)
__CMPXCHG_CASE(acq_,  8)
__CMPXCHG_CASE(acq_, 16)
__CMPXCHG_CASE(acq_, 32)
__CMPXCHG_CASE(acq_, 64)
__CMPXCHG_CASE(rel_,  8)
__CMPXCHG_CASE(rel_, 16)
__CMPXCHG_CASE(rel_, 32)
__CMPXCHG_CASE(rel_, 64)
__CMPXCHG_CASE(mb_,  8)
__CMPXCHG_CASE(mb_, 16)
__CMPXCHG_CASE(mb_, 32)
__CMPXCHG_CASE(mb_, 64)

#undef __CMPXCHG_CASE

#define __CMPXCHG_DBL(name)						\
static inline long __cmpxchg_double##name(unsigned long old1,		\
					 unsigned long old2,		\
					 unsigned long new1,		\
					 unsigned long new2,		\
					 volatile void *ptr)		\
{									\
	return __lse_ll_sc_body(_cmpxchg_double##name, 			\
				old1, old2, new1, new2, ptr);		\
}

__CMPXCHG_DBL(   )
__CMPXCHG_DBL(_mb)

#undef __CMPXCHG_DBL

#define __CMPXCHG_GEN(sfx)						\
static __always_inline unsigned long __cmpxchg##sfx(volatile void *ptr,	\
					   unsigned long old,		\
					   unsigned long new,		\
					   int size)			\
{									\
	switch (size) {							\
	case 1:								\
		return __cmpxchg_case##sfx##_8(ptr, old, new);		\
	case 2:								\
		return __cmpxchg_case##sfx##_16(ptr, old, new);		\
	case 4:								\
		return __cmpxchg_case##sfx##_32(ptr, old, new);		\
	case 8:								\
		return __cmpxchg_case##sfx##_64(ptr, old, new);		\
	default:							\
		BUILD_BUG();						\
	}								\
									\
	unreachable();							\
}

__CMPXCHG_GEN()
__CMPXCHG_GEN(_acq)
__CMPXCHG_GEN(_rel)
__CMPXCHG_GEN(_mb)

#undef __CMPXCHG_GEN

#define __cmpxchg_wrapper(sfx, ptr, o, n)				\
({									\
	__typeof__(*(ptr)) __ret;					\
	__ret = (__typeof__(*(ptr)))					\
		__cmpxchg##sfx((ptr), (unsigned long)(o),		\
				(unsigned long)(n), sizeof(*(ptr)));	\
	__ret;								\
})

/* cmpxchg */
#define arch_cmpxchg_relaxed(...)	__cmpxchg_wrapper(    , __VA_ARGS__)
#define arch_cmpxchg_acquire(...)	__cmpxchg_wrapper(_acq, __VA_ARGS__)
#define arch_cmpxchg_release(...)	__cmpxchg_wrapper(_rel, __VA_ARGS__)
#define arch_cmpxchg(...)		__cmpxchg_wrapper( _mb, __VA_ARGS__)
#define arch_cmpxchg_local		arch_cmpxchg_relaxed

/* cmpxchg64 */
#define arch_cmpxchg64_relaxed		arch_cmpxchg_relaxed
#define arch_cmpxchg64_acquire		arch_cmpxchg_acquire
#define arch_cmpxchg64_release		arch_cmpxchg_release
#define arch_cmpxchg64			arch_cmpxchg
#define arch_cmpxchg64_local		arch_cmpxchg_local

/* cmpxchg_double */
#define system_has_cmpxchg_double()     1

#define __cmpxchg_double_check(ptr1, ptr2)					\
({										\
	if (sizeof(*(ptr1)) != 8)						\
		BUILD_BUG();							\
	VM_BUG_ON((unsigned long *)(ptr2) - (unsigned long *)(ptr1) != 1);	\
})

#define arch_cmpxchg_double(ptr1, ptr2, o1, o2, n1, n2)				\
({										\
	int __ret;								\
	__cmpxchg_double_check(ptr1, ptr2);					\
	__ret = !__cmpxchg_double_mb((unsigned long)(o1), (unsigned long)(o2),	\
				     (unsigned long)(n1), (unsigned long)(n2),	\
				     ptr1);					\
	__ret;									\
})

#define arch_cmpxchg_double_local(ptr1, ptr2, o1, o2, n1, n2)			\
({										\
	int __ret;								\
	__cmpxchg_double_check(ptr1, ptr2);					\
	__ret = !__cmpxchg_double((unsigned long)(o1), (unsigned long)(o2),	\
				  (unsigned long)(n1), (unsigned long)(n2),	\
				  ptr1);					\
	__ret;									\
})
/*
 * IAMROOT, 2021.09.18:
 * - sevl : send event to local cpu
 * - wfe : wait for event. event register가 0일때는 wait. 1일때는 무조건 깨어남.
 *   
 * - sevl, wfe를 하는 이유
 *   해당 code가 들어오기전에 이미 다른 곳에서 event stream등의 발생 이유로
 *   event register가 차있을수도 있기떄문에,
 *   무조건 한번 발생시키고 wfe를 함으로써 event register를 비우기 위함이다.
 *   arm32까지만해도 wfe{cond} 명령어가 있었는데 없어지면서 이런방식을 쓰게됬다.
 *
 * - cbnz후에 wfe를 하는 이유
 *   loop check를 할경우, sleep관련 명령어가 없을경우 1초에 몇억번을 수행할 수 있는데
 *   이를 방지하기 위해 일종의 sleep 개념인 wfe를 사용하였다.
 *   wfe는 다른 cpu의 event stream, sevl, 그리고 ldxr명령어를 통해서 깨어나게 되어
 *   어느정도 sleep을 할 수 있는 환경을 만든다.
 *
 * - ldxr, eor, cbnz : *ptr과 val값이 동일하면 wait, 아니면 빠져나옴.
 */
#define __CMPWAIT_CASE(w, sfx, sz)					\
static inline void __cmpwait_case_##sz(volatile void *ptr,		\
				       unsigned long val)		\
{									\
	unsigned long tmp;						\
									\
	asm volatile(							\
	"	sevl\n"							\
	"	wfe\n"							\
	"	ldxr" #sfx "\t%" #w "[tmp], %[v]\n"			\
	"	eor	%" #w "[tmp], %" #w "[tmp], %" #w "[val]\n"	\
	"	cbnz	%" #w "[tmp], 1f\n"				\
	"	wfe\n"							\
	"1:"								\
	: [tmp] "=&r" (tmp), [v] "+Q" (*(unsigned long *)ptr)		\
	: [val] "r" (val));						\
}

__CMPWAIT_CASE(w, b, 8);
__CMPWAIT_CASE(w, h, 16);
__CMPWAIT_CASE(w,  , 32);
__CMPWAIT_CASE( ,  , 64);

#undef __CMPWAIT_CASE

#define __CMPWAIT_GEN(sfx)						\
static __always_inline void __cmpwait##sfx(volatile void *ptr,		\
				  unsigned long val,			\
				  int size)				\
{									\
	switch (size) {							\
	case 1:								\
		return __cmpwait_case##sfx##_8(ptr, (u8)val);		\
	case 2:								\
		return __cmpwait_case##sfx##_16(ptr, (u16)val);		\
	case 4:								\
		return __cmpwait_case##sfx##_32(ptr, val);		\
	case 8:								\
		return __cmpwait_case##sfx##_64(ptr, val);		\
	default:							\
		BUILD_BUG();						\
	}								\
									\
	unreachable();							\
}

__CMPWAIT_GEN()

#undef __CMPWAIT_GEN

#define __cmpwait_relaxed(ptr, val) \
	__cmpwait((ptr), (unsigned long)(val), sizeof(*(ptr)))

#endif	/* __ASM_CMPXCHG_H */
