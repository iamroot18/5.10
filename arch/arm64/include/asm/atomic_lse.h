/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/atomic.h
 *
 * Copyright (C) 1996 Russell King.
 * Copyright (C) 2002 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __ASM_ATOMIC_LSE_H
#define __ASM_ATOMIC_LSE_H
/*
 * IAMROOT, 2021.09.18:
 * - asm_op : asm 이 만들어질때 실제 op에 해당하는 instruction
 * - [n] : n에 해당하는 register 번호
 *   [i] : 인자 i(값)가 할당된 register 번호
 *   [v] : v->counter(주소)가 할당된 register 번호
 */
#define ATOMIC_OP(op, asm_op)						\
static inline void __lse_atomic_##op(int i, atomic_t *v)			\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
"	" #asm_op "	%w[i], %[v]\n"					\
	: [i] "+r" (i), [v] "+Q" (v->counter)				\
	: "r" (v));							\
}

/*
 * IAMROOT, 2021.11.07:
 * stclr: Atomic bit clear on word or doubleword in memory, without return.
 * stset: Atomic bit set on word or doubleword in memory, without return.
 * steor: Atomic exclusive OR on word or doubleword in memory, without return.
 * stadd: Atomic add on word or doubleword in memory, without return.
 *
 * From Arm Compiler armasm User Guide.
 * https://developer.arm.com/documentation/100069/latest.
 */
ATOMIC_OP(andnot, stclr)
ATOMIC_OP(or, stset)
ATOMIC_OP(xor, steor)
ATOMIC_OP(add, stadd)

#undef ATOMIC_OP
/*
 * IAMROOT, 2021.09.18:
 * - ex. ATOMIC_FETCH_OPS(add, ldadd)
 *   asm instruction이 mb(memory barrier)에 따라 다음과 같이 된다.
 *   ((없음), a, l, al) (a: acquire, l: release)
 *   ldadd, ldadda, ldaddl, ldaddal
 *
 * - ldadd Xs, Xt, [Xn/SP]
 *     : Atomic add on word or doubleword in memory.
 *       It atomically loads a 32-bit word from memory, adds the value
 *       held in a register to it, and stores the result back to memory.
 *       The value initially loaded from memory is returned in the destination register.
 *       - Xs: 레지스터 (메모리에 들어있는 값에 더할 값)
 *       - Xt: 레지스터 (더하기 전에 메모리에 들어있는 값)
 *       - Xn/SP: 메모리 주소 (Base register or Stack Pointer)
 *   (위의 stadd랑 비슷하지만 stadd에는 Xt가 없다.)
 *
 * - fetch는 old값을 return 한다.
 *
 * - __lse_atomic_fetch_##op##name 설명
 *   - v->counter에 atomic하게 i를 op한다.
 *   - v->counter의 old value를 로컬 변수 i에 덮어쓰고 return한다.
 */
#define ATOMIC_FETCH_OP(name, mb, op, asm_op, cl...)			\
static inline int __lse_atomic_fetch_##op##name(int i, atomic_t *v)	\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
"	" #asm_op #mb "	%w[i], %w[i], %[v]"				\
	: [i] "+r" (i), [v] "+Q" (v->counter)				\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

#define ATOMIC_FETCH_OPS(op, asm_op)					\
	ATOMIC_FETCH_OP(_relaxed,   , op, asm_op)			\
	ATOMIC_FETCH_OP(_acquire,  a, op, asm_op, "memory")		\
	ATOMIC_FETCH_OP(_release,  l, op, asm_op, "memory")		\
	ATOMIC_FETCH_OP(        , al, op, asm_op, "memory")

ATOMIC_FETCH_OPS(andnot, ldclr)
ATOMIC_FETCH_OPS(or, ldset)
ATOMIC_FETCH_OPS(xor, ldeor)
ATOMIC_FETCH_OPS(add, ldadd)

#undef ATOMIC_FETCH_OP
#undef ATOMIC_FETCH_OPS

/*
 * IAMROOT, 2021.11.07:
 * - return은 new값을 return 한다.
 *
 * __lse_atomic_add_return##name 설명
 *   - v->counter에 atomic하게 i를 add한다.
 *   - v->counter의 old value를 로컬 변수 tmp에 write하고
 *     tmp에 i를 add한 후 tmp를 return한다.
 */
#define ATOMIC_OP_ADD_RETURN(name, mb, cl...)				\
static inline int __lse_atomic_add_return##name(int i, atomic_t *v)	\
{									\
	u32 tmp;							\
									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	ldadd" #mb "	%w[i], %w[tmp], %[v]\n"			\
	"	add	%w[i], %w[i], %w[tmp]"				\
	: [i] "+r" (i), [v] "+Q" (v->counter), [tmp] "=&r" (tmp)	\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC_OP_ADD_RETURN(_relaxed,   )
ATOMIC_OP_ADD_RETURN(_acquire,  a, "memory")
ATOMIC_OP_ADD_RETURN(_release,  l, "memory")
ATOMIC_OP_ADD_RETURN(        , al, "memory")

#undef ATOMIC_OP_ADD_RETURN

/*
 * IAMROOT, 2021.11.07:
 * mvn: Bitwise NOT (vector)
 *
 * __lse_atomic_and 설명
 * - i에 not을 취한다. (0->1, 1->0)
 * - i를 가지고 v->counter를 clear한다. (i의 bit가 1이면 v->counter의 bit는 0이 된다.)
 */
static inline void __lse_atomic_and(int i, atomic_t *v)
{
	asm volatile(
	__LSE_PREAMBLE
	"	mvn	%w[i], %w[i]\n"
	"	stclr	%w[i], %[v]"
	: [i] "+&r" (i), [v] "+Q" (v->counter)
	: "r" (v));
}

/*
 * IAMROOT, 2021.11.08:
 * - i에 not을 취한다.
 * - i를 가지고 v->counter를 clear한다. (i의 bit가 1이면 v->counter의 bit는 0이 된다.)
 * - i에 v->counter의 old값을 write한다.
 */
#define ATOMIC_FETCH_OP_AND(name, mb, cl...)				\
static inline int __lse_atomic_fetch_and##name(int i, atomic_t *v)	\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	mvn	%w[i], %w[i]\n"					\
	"	ldclr" #mb "	%w[i], %w[i], %[v]"			\
	: [i] "+&r" (i), [v] "+Q" (v->counter)				\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC_FETCH_OP_AND(_relaxed,   )
ATOMIC_FETCH_OP_AND(_acquire,  a, "memory")
ATOMIC_FETCH_OP_AND(_release,  l, "memory")
ATOMIC_FETCH_OP_AND(        , al, "memory")

#undef ATOMIC_FETCH_OP_AND

/*
 * IAMROOT, 2021.11.08:
 * - neg: negate (vector)
 *     - 양수->음수, 음수->양수
 *
 * __lse_atomic_sub 설명
 * - i의 부호를 바꾼다.
 * - v->counter에 atomic하게 i를 add한다.
 */
static inline void __lse_atomic_sub(int i, atomic_t *v)
{
	asm volatile(
	__LSE_PREAMBLE
	"	neg	%w[i], %w[i]\n"
	"	stadd	%w[i], %[v]"
	: [i] "+&r" (i), [v] "+Q" (v->counter)
	: "r" (v));
}

/*
 * IAMROOT, 2021.11.08:
 * - i의 부호를 바꾼다.
 * - v->counter에 atomic하게 i를 add한다.
 * - v->counter의 old 값을 tmp에 write한다.
 * - i에 tmp를 더하고 i를 return한다.
 */
#define ATOMIC_OP_SUB_RETURN(name, mb, cl...)				\
static inline int __lse_atomic_sub_return##name(int i, atomic_t *v)	\
{									\
	u32 tmp;							\
									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	neg	%w[i], %w[i]\n"					\
	"	ldadd" #mb "	%w[i], %w[tmp], %[v]\n"			\
	"	add	%w[i], %w[i], %w[tmp]"				\
	: [i] "+&r" (i), [v] "+Q" (v->counter), [tmp] "=&r" (tmp)	\
	: "r" (v)							\
	: cl);							\
									\
	return i;							\
}

ATOMIC_OP_SUB_RETURN(_relaxed,   )
ATOMIC_OP_SUB_RETURN(_acquire,  a, "memory")
ATOMIC_OP_SUB_RETURN(_release,  l, "memory")
ATOMIC_OP_SUB_RETURN(        , al, "memory")

#undef ATOMIC_OP_SUB_RETURN

/*
 * IAMROOT, 2021.11.08:
 * - i의 부호를 바꾼다.
 * - v->counter에 atomic하게 i를 add한다.
 * - v->counter의 old 값을 i에 write한다.
 * - i를 return한다. (old 값)
 */
#define ATOMIC_FETCH_OP_SUB(name, mb, cl...)				\
static inline int __lse_atomic_fetch_sub##name(int i, atomic_t *v)	\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	neg	%w[i], %w[i]\n"					\
	"	ldadd" #mb "	%w[i], %w[i], %[v]"			\
	: [i] "+&r" (i), [v] "+Q" (v->counter)				\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC_FETCH_OP_SUB(_relaxed,   )
ATOMIC_FETCH_OP_SUB(_acquire,  a, "memory")
ATOMIC_FETCH_OP_SUB(_release,  l, "memory")
ATOMIC_FETCH_OP_SUB(        , al, "memory")

#undef ATOMIC_FETCH_OP_SUB

#define ATOMIC64_OP(op, asm_op)						\
static inline void __lse_atomic64_##op(s64 i, atomic64_t *v)		\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
"	" #asm_op "	%[i], %[v]\n"					\
	: [i] "+r" (i), [v] "+Q" (v->counter)				\
	: "r" (v));							\
}

ATOMIC64_OP(andnot, stclr)
ATOMIC64_OP(or, stset)
ATOMIC64_OP(xor, steor)
ATOMIC64_OP(add, stadd)

#undef ATOMIC64_OP

#define ATOMIC64_FETCH_OP(name, mb, op, asm_op, cl...)			\
static inline long __lse_atomic64_fetch_##op##name(s64 i, atomic64_t *v)\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
"	" #asm_op #mb "	%[i], %[i], %[v]"				\
	: [i] "+r" (i), [v] "+Q" (v->counter)				\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

#define ATOMIC64_FETCH_OPS(op, asm_op)					\
	ATOMIC64_FETCH_OP(_relaxed,   , op, asm_op)			\
	ATOMIC64_FETCH_OP(_acquire,  a, op, asm_op, "memory")		\
	ATOMIC64_FETCH_OP(_release,  l, op, asm_op, "memory")		\
	ATOMIC64_FETCH_OP(        , al, op, asm_op, "memory")

ATOMIC64_FETCH_OPS(andnot, ldclr)
ATOMIC64_FETCH_OPS(or, ldset)
ATOMIC64_FETCH_OPS(xor, ldeor)
ATOMIC64_FETCH_OPS(add, ldadd)

#undef ATOMIC64_FETCH_OP
#undef ATOMIC64_FETCH_OPS

#define ATOMIC64_OP_ADD_RETURN(name, mb, cl...)				\
static inline long __lse_atomic64_add_return##name(s64 i, atomic64_t *v)\
{									\
	unsigned long tmp;						\
									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	ldadd" #mb "	%[i], %x[tmp], %[v]\n"			\
	"	add	%[i], %[i], %x[tmp]"				\
	: [i] "+r" (i), [v] "+Q" (v->counter), [tmp] "=&r" (tmp)	\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC64_OP_ADD_RETURN(_relaxed,   )
ATOMIC64_OP_ADD_RETURN(_acquire,  a, "memory")
ATOMIC64_OP_ADD_RETURN(_release,  l, "memory")
ATOMIC64_OP_ADD_RETURN(        , al, "memory")

#undef ATOMIC64_OP_ADD_RETURN

static inline void __lse_atomic64_and(s64 i, atomic64_t *v)
{
	asm volatile(
	__LSE_PREAMBLE
	"	mvn	%[i], %[i]\n"
	"	stclr	%[i], %[v]"
	: [i] "+&r" (i), [v] "+Q" (v->counter)
	: "r" (v));
}

#define ATOMIC64_FETCH_OP_AND(name, mb, cl...)				\
static inline long __lse_atomic64_fetch_and##name(s64 i, atomic64_t *v)	\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	mvn	%[i], %[i]\n"					\
	"	ldclr" #mb "	%[i], %[i], %[v]"			\
	: [i] "+&r" (i), [v] "+Q" (v->counter)				\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC64_FETCH_OP_AND(_relaxed,   )
ATOMIC64_FETCH_OP_AND(_acquire,  a, "memory")
ATOMIC64_FETCH_OP_AND(_release,  l, "memory")
ATOMIC64_FETCH_OP_AND(        , al, "memory")

#undef ATOMIC64_FETCH_OP_AND

static inline void __lse_atomic64_sub(s64 i, atomic64_t *v)
{
	asm volatile(
	__LSE_PREAMBLE
	"	neg	%[i], %[i]\n"
	"	stadd	%[i], %[v]"
	: [i] "+&r" (i), [v] "+Q" (v->counter)
	: "r" (v));
}

#define ATOMIC64_OP_SUB_RETURN(name, mb, cl...)				\
static inline long __lse_atomic64_sub_return##name(s64 i, atomic64_t *v)	\
{									\
	unsigned long tmp;						\
									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	neg	%[i], %[i]\n"					\
	"	ldadd" #mb "	%[i], %x[tmp], %[v]\n"			\
	"	add	%[i], %[i], %x[tmp]"				\
	: [i] "+&r" (i), [v] "+Q" (v->counter), [tmp] "=&r" (tmp)	\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC64_OP_SUB_RETURN(_relaxed,   )
ATOMIC64_OP_SUB_RETURN(_acquire,  a, "memory")
ATOMIC64_OP_SUB_RETURN(_release,  l, "memory")
ATOMIC64_OP_SUB_RETURN(        , al, "memory")

#undef ATOMIC64_OP_SUB_RETURN

#define ATOMIC64_FETCH_OP_SUB(name, mb, cl...)				\
static inline long __lse_atomic64_fetch_sub##name(s64 i, atomic64_t *v)	\
{									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	neg	%[i], %[i]\n"					\
	"	ldadd" #mb "	%[i], %[i], %[v]"			\
	: [i] "+&r" (i), [v] "+Q" (v->counter)				\
	: "r" (v)							\
	: cl);								\
									\
	return i;							\
}

ATOMIC64_FETCH_OP_SUB(_relaxed,   )
ATOMIC64_FETCH_OP_SUB(_acquire,  a, "memory")
ATOMIC64_FETCH_OP_SUB(_release,  l, "memory")
ATOMIC64_FETCH_OP_SUB(        , al, "memory")

#undef ATOMIC64_FETCH_OP_SUB

static inline s64 __lse_atomic64_dec_if_positive(atomic64_t *v)
{
	unsigned long tmp;

	asm volatile(
	__LSE_PREAMBLE
	"1:	ldr	%x[tmp], %[v]\n"
	"	subs	%[ret], %x[tmp], #1\n"
	"	b.lt	2f\n"
	"	casal	%x[tmp], %[ret], %[v]\n"
	"	sub	%x[tmp], %x[tmp], #1\n"
	"	sub	%x[tmp], %x[tmp], %[ret]\n"
	"	cbnz	%x[tmp], 1b\n"
	"2:"
	: [ret] "+&r" (v), [v] "+Q" (v->counter), [tmp] "=&r" (tmp)
	:
	: "cc", "memory");

	return (long)v;
}
/*
 * IAMROOT, 2021.09.18:
 * - cas : compare and swap
 *
 * - CAS Xs, Xt, [Xn|SP]       : 64bit
 *   CAS{B|H|} Ws, Wt, [Xn|SP] : 8, 16, 32bit
 *   Xs or Ws 값 <- [Xn|SP] (load and compare)
 *   [Xn|SP] <- Xt or Wt 값 (store when equal)
 *
 *   어떤 메모리 주소(Xn/SP)에 있는 값을 읽어와 Xs값과 비교하여
 *   동일하면 새로운 값(Xt)을 같은 메모리 주소에 기록한다.
 *   이때 메모리 주소로부터 읽어온 값은 'Xt값 저장 성공 여부'에
 *   상관없이 Xs에 저장하며 이 모든 과정들은 atomic하게 이루어진다.
 */
#define __CMPXCHG_CASE(w, sfx, name, sz, mb, cl...)			\
static __always_inline u##sz						\
__lse__cmpxchg_case_##name##sz(volatile void *ptr,			\
					      u##sz old,		\
					      u##sz new)		\
{									\
	register unsigned long x0 asm ("x0") = (unsigned long)ptr;	\
	register u##sz x1 asm ("x1") = old;				\
	register u##sz x2 asm ("x2") = new;				\
	unsigned long tmp;						\
									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	mov	%" #w "[tmp], %" #w "[old]\n"			\
	"	cas" #mb #sfx "\t%" #w "[tmp], %" #w "[new], %[v]\n"	\
	"	mov	%" #w "[ret], %" #w "[tmp]"			\
	: [ret] "+r" (x0), [v] "+Q" (*(unsigned long *)ptr),		\
	  [tmp] "=&r" (tmp)						\
	: [old] "r" (x1), [new] "r" (x2)				\
	: cl);								\
									\
	return x0;							\
}

__CMPXCHG_CASE(w, b,     ,  8,   )
__CMPXCHG_CASE(w, h,     , 16,   )
__CMPXCHG_CASE(w,  ,     , 32,   )
__CMPXCHG_CASE(x,  ,     , 64,   )
__CMPXCHG_CASE(w, b, acq_,  8,  a, "memory")
__CMPXCHG_CASE(w, h, acq_, 16,  a, "memory")
__CMPXCHG_CASE(w,  , acq_, 32,  a, "memory")
__CMPXCHG_CASE(x,  , acq_, 64,  a, "memory")
__CMPXCHG_CASE(w, b, rel_,  8,  l, "memory")
__CMPXCHG_CASE(w, h, rel_, 16,  l, "memory")
__CMPXCHG_CASE(w,  , rel_, 32,  l, "memory")
__CMPXCHG_CASE(x,  , rel_, 64,  l, "memory")
__CMPXCHG_CASE(w, b,  mb_,  8, al, "memory")
__CMPXCHG_CASE(w, h,  mb_, 16, al, "memory")
__CMPXCHG_CASE(w,  ,  mb_, 32, al, "memory")
__CMPXCHG_CASE(x,  ,  mb_, 64, al, "memory")

#undef __CMPXCHG_CASE

#define __CMPXCHG_DBL(name, mb, cl...)					\
static __always_inline long						\
__lse__cmpxchg_double##name(unsigned long old1,				\
					 unsigned long old2,		\
					 unsigned long new1,		\
					 unsigned long new2,		\
					 volatile void *ptr)		\
{									\
	unsigned long oldval1 = old1;					\
	unsigned long oldval2 = old2;					\
	register unsigned long x0 asm ("x0") = old1;			\
	register unsigned long x1 asm ("x1") = old2;			\
	register unsigned long x2 asm ("x2") = new1;			\
	register unsigned long x3 asm ("x3") = new2;			\
	register unsigned long x4 asm ("x4") = (unsigned long)ptr;	\
									\
	asm volatile(							\
	__LSE_PREAMBLE							\
	"	casp" #mb "\t%[old1], %[old2], %[new1], %[new2], %[v]\n"\
	"	eor	%[old1], %[old1], %[oldval1]\n"			\
	"	eor	%[old2], %[old2], %[oldval2]\n"			\
	"	orr	%[old1], %[old1], %[old2]"			\
	: [old1] "+&r" (x0), [old2] "+&r" (x1),				\
	  [v] "+Q" (*(unsigned long *)ptr)				\
	: [new1] "r" (x2), [new2] "r" (x3), [ptr] "r" (x4),		\
	  [oldval1] "r" (oldval1), [oldval2] "r" (oldval2)		\
	: cl);								\
									\
	return x0;							\
}

__CMPXCHG_DBL(   ,   )
__CMPXCHG_DBL(_mb, al, "memory")

#undef __CMPXCHG_DBL

#endif	/* __ASM_ATOMIC_LSE_H */
