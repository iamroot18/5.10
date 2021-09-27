/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_FLS64_H_
#define _ASM_GENERIC_BITOPS_FLS64_H_

#include <asm/types.h>

/**
 * fls64 - find last set bit in a 64-bit word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffsll, but returns the position of the most significant set bit.
 *
 * fls64(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 64.
 */
#if BITS_PER_LONG == 32
/* IAMROOT, 2021.09.27:
 * 32번 bit이상에 set bit가 존재할경우 x >> 32로 값이 남고, 최소값이 32보다
 * 클것이므로 32를 더해주고 그게 아니면 32bit 처리하는것처럼 처리한다.
 */
static __always_inline int fls64(__u64 x)
{
	__u32 h = x >> 32;
	if (h)
		return fls(h) + 32;
	return fls(x);
}
#elif BITS_PER_LONG == 64
/* IAMROOT, 2021.09.27:
 * long형이 64bit일 경우 __builtin_clzl(__fls)로만으로 처리가 가능하므로,
 * 해당 함수 처리조건인 0검사, __가 없는 fls는 0번 bit가 1인것을 고려한 + 1처리를
 * 해준다.
 */
static __always_inline int fls64(__u64 x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}
#else
#error BITS_PER_LONG not 32 or 64
#endif

#endif /* _ASM_GENERIC_BITOPS_FLS64_H_ */
