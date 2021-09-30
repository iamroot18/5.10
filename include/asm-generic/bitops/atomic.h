/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_ATOMIC_H_
#define _ASM_GENERIC_BITOPS_ATOMIC_H_

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <asm/barrier.h>

/* IAMROOT, 2021.09.29:
 * - arch/arm64/include/asm/bitops.h에서 현재 header를 include하고 있음이 보인다.
 * - bitmap을 고려한 설계라 BIT_WORD로 bitmap index를 구한다.
 * - nr이 상수가 와야 compile time에 계산되 최적화가 되는데,
 *   변수가 오면 runtime에 BIT_WORD, BIT_MASK등이 계산되야되므로 성능하락이된다.
 */

/*
 * Implementation of atomic bitops using atomic-fetch ops.
 * See Documentation/atomic_bitops.txt for details.
 */

static inline void set_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	atomic_long_or(BIT_MASK(nr), (atomic_long_t *)p);
}

static inline void clear_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	atomic_long_andnot(BIT_MASK(nr), (atomic_long_t *)p);
}

/* IAMROOT, 2021.09.29:
 * - xor
 */
static inline void change_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	atomic_long_xor(BIT_MASK(nr), (atomic_long_t *)p);
}

/* IAMROOT, 2021.09.29:
 * - test류는 전부 fetch의 개념이므로 그 전에 set되있던 값을 가져온다.
 *   다만 여기선 0과 1만을 return하기 위해 !!등이 사용한것이 보인다.
 *
 * - test_and_set_bit, test_and_clear_bit의 경우 nr이 해당 값이면 별 동작안하고
 *   바로 return을 하여 속도향상을 꾀한다.
 *   test_and_change_bit는 어쨋든 bit를 건드려야되므로 READ_ONCE를 안한다.
 */
static inline int test_and_set_bit(unsigned int nr, volatile unsigned long *p)
{
	long old;
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);
	if (READ_ONCE(*p) & mask)
		return 1;

	old = atomic_long_fetch_or(mask, (atomic_long_t *)p);
	return !!(old & mask);
}

static inline int test_and_clear_bit(unsigned int nr, volatile unsigned long *p)
{
	long old;
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);
	if (!(READ_ONCE(*p) & mask))
		return 0;

	old = atomic_long_fetch_andnot(mask, (atomic_long_t *)p);
	return !!(old & mask);
}

static inline int test_and_change_bit(unsigned int nr, volatile unsigned long *p)
{
	long old;
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);
	old = atomic_long_fetch_xor(mask, (atomic_long_t *)p);
	return !!(old & mask);
}

#endif /* _ASM_GENERIC_BITOPS_ATOMIC_H */
