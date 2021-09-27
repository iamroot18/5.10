/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_BUILTIN___FFS_H_
#define _ASM_GENERIC_BITOPS_BUILTIN___FFS_H_

/* IAMROOT, 2021.09.27:
 * - ex. 0b....1000
 *   3이 return된다. __fls처럼 0이 오는경우 Undefined 이다.
 *
 * - ffs 함수에서는 __builtin_ffs를 사용했는데 여기선 __builtin_ctz류 함수를
 * 사용한것이 눈에 띈다.
 *
 * - __builtin_ctzl : long형의 __builtin_ctz. LSB부터 1이 나오기전까지 0의 개수
 */
/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}

#endif
