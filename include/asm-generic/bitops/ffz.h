/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_FFZ_H_
#define _ASM_GENERIC_BITOPS_FFZ_H_

/* IAMROOT, 2021.09.27:
 * - __ffs가 0를 허용하지 않았으므로 ~0를 허용하지 않을 것이다.
 *
 * - __ffs가 set bit를 찾는 거였으므로 다음과 같이 이루어진다.
 *   ex) 0b0000_1111 -> ~0b0000_1111 = 0b1111_0000 -> set bit를 찾음
 *   -> 4번bit가 set이므로 4 return.
 *   이런식으로 lsb에서 최초에 0인 bit번호를 찾게 되는것이다.
 */
/*
 * ffz - find first zero in word.
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
#define ffz(x)  __ffs(~(x))

#endif /* _ASM_GENERIC_BITOPS_FFZ_H_ */
