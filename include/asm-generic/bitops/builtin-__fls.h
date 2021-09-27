/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_BUILTIN___FLS_H_
#define _ASM_GENERIC_BITOPS_BUILTIN___FLS_H_

/* IAMROOT, 2021.09.27:
 * - ex. x = 0b...1001_0000
 *   __builtin_clzl(x) = 24
 *   __fls(x) = 7
 *
 * - __builtin_clzl : __builtin_clz의 long형 버전. (fls 함수 참고)
 *
 * - 0번 bit만 1일 경우 0으로 return. 그러므로 word값이 0일경우
 *   __builtin_clzl 동작도 부정확하고 return값 자체도 맞지 않아
 *   0인지 확인을 미리 해줘야된다는것.
 */
/**
 * __fls - find last (most-significant) set bit in a long word
 * @word: the word to search
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 */
static __always_inline unsigned long __fls(unsigned long word)
{
	return (sizeof(word) * 8) - 1 - __builtin_clzl(word);
}

#endif
