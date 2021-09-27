/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_BUILTIN_FLS_H_
#define _ASM_GENERIC_BITOPS_BUILTIN_FLS_H_

/* IAMROOT, 2021.09.27:
 * - ex. x = 0b...1001_0000
 *   __builtin_clz(x) = 24
 *   fls(x) = 8
 *
 * - __builtin_clz
 *   msb bit부터 1이 나오기전 0의 개수
 *   인자값이 0이고 이 값이 변수인경우 예측불가능한 값을 내놓는다.
 *   (x가 상수면 컴파일러 최적화로 인해 그냥 32로 나온다)
 *
 * - 0번bit만 1일 경우 1로 return.
 */
/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
static __always_inline int fls(unsigned int x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

#endif
