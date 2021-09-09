/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 ARM Ltd.
 * Copyright (C) 2013 Linaro.
 *
 * This code is based on glibc cortex strings work originally authored by Linaro
 * be found @
 *
 * http://bazaar.launchpad.net/~linaro-toolchain-dev/cortex-strings/trunk/
 * files/head:/src/aarch64/
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/cache.h>

/*
 * Fill in the buffer with character c (alignment handled by the hardware)
 *
 * Parameters:
 *	x0 - buf
 *	x1 - c
 *	x2 - n
 * Returns:
 *	x0 - buf
 */

dstin		.req	x0
val		.req	w1
count		.req	x2
tmp1		.req	x3
tmp1w		.req	w3
tmp2		.req	x4
tmp2w		.req	w4
zva_len_x	.req	x5
zva_len		.req	w5
zva_bits_x	.req	x6

A_l		.req	x7
A_lw		.req	w7
dst		.req	x8
tmp3w		.req	w9
tmp3		.req	x9

SYM_FUNC_START_ALIAS(__memset)
SYM_FUNC_START_WEAK_PI(memset)
/*
 * IAMROOT, 2021.09.07:
 * val값을 base로 하여 x7(A_L, 64-bits) reg에 복사한다.
 * val = 0x0A(1 byte)라고 가정하면
 * - A_lw(0x0A)       = 0x0A & 0xFF
 * - A_lw(0x0A0A)     = 0x000A (A_lw) + 0x0A00 (0x000A << 8) (A_lw)
 * - A_lw(0x0A0A0A0A) = 0x00000A0A (A_lw) + 0x0A0A0000 (0x00000A0A << 16) (A_lw)
 * - A_l(0x0A0A0A0A0A0A0A0A) =
 *     0x000000000A0A0A0A (A_l) + 0x0A0A0A0A00000000 (0x000000000A0A0A0A << 32) (A_l)
 * - x7(A_l) = 0x0A0A0A0A0A0A0A0A
 */
	mov	dst, dstin	/* Preserve return value.  */
	and	A_lw, val, #255
	orr	A_lw, A_lw, A_lw, lsl #8
	orr	A_lw, A_lw, A_lw, lsl #16
	orr	A_l, A_l, A_l, lsl #32
/*
 * IAMROOT, 2021.09.09:
 * - 복사할 값(0x0A)을 x7 reg에 준비. 아직 메모리에 쓰지 않았으며
 *   x2(요청 사이즈)에 따라 처리 루틴이 달라진다.
 */

	cmp	count, #15
	b.hi	.Lover16_proc
/*
 * IAMROOT, 2021.09.07:
 * 복사할 값이 15byte 이하인 경우 진입했으므로 4번 비트 이상이 set되 있을수가
 * 없다. 3번 bit가 clear면 8바이트 미만이므로 1f로 넘어가고
 * 그게 아니면 dst 부터 8byte를 복사하고 dst += 8을 수행한다.
 */
	/*All store maybe are non-aligned..*/
	tbz	count, #3, 1f
	str	A_l, [dst], #8
1:
/*
 * IAMROOT, 2021.09.07:
 * 위와 원리는 동일 하다. 2번째 bit를 검사하므로 4byte미만이면 다음으로 넘어가고
 * 아니라면 4byte를 복사하고 복사한 크기만큼 dst를 증가시킨다.
 *
 * 즉 N번째 bit검사를 함으로써 8byte -> 4byte -> 2 byte -> 1byte 복사를 하면서
 * dst도 증가시킨다..
 */
	tbz	count, #2, 2f
	str	A_lw, [dst], #4
2:
	tbz	count, #1, 3f
	strh	A_lw, [dst], #2
3:
	tbz	count, #0, 4f
	strb	A_lw, [dst]
4:
	ret

.Lover16_proc:
/*
 * IAMROOT, 2021.09.07:
 * neg: 인자의 2의 보수를 계산한다.
 *
 * 2의 보수를 취하고 0xf를 and해 16byte정렬 값인지를 검사한다.
 * 16byte 정렬되있으면 해당 값의 보수값은 0xXXXX..XX0 이기 때문이다.
 */
	/*Whether  the start address is aligned with 16.*/
	neg	tmp2, dst
	ands	tmp2, tmp2, #15
	b.eq	.Laligned
/*
 * IAMROOT, 2021.09.07:
 *
 * 2의 보수를 취하고 0xf를 and해 16byte정렬 값인지를 검사한다.
 * 16byte 정렬되있으면 해당 값의 보수값은 0xXXXX..XX0 이기 때문이다.
 *
 * 정렬이 안되있으면 무조건 16byte를 일단 복사한다. 이 코드가 실행되는 시점엔
 * 이미 size는 16byte보다 크므로 size이외의 영역이 store 될일은 없다.
 * 다만 같은 주소를 최초에 한번 더 store할 수 있긴하다.
 * 일단 16byte를 복사하고 나서 dst를 16byte 정렬주소로 맞추기 위해
 * 위에서 0xf로 나머지 구한값을 dst에 더해준다.
 */
/*
* The count is not less than 16, we can use stp to store the start 16 bytes,
* then adjust the dst aligned with 16.This process will make the current
* memory address at alignment boundary.
*/
	stp	A_l, A_l, [dst] /*non-aligned store..*/
	/*make the dst aligned..*/
	sub	count, count, tmp2
	add	dst, dst, tmp2

.Laligned:
	cbz	A_l, .Lzero_mem

.Ltail_maybe_long:
	cmp	count, #64
	b.ge	.Lnot_short
.Ltail63:
	ands	tmp1, count, #0x30
	b.eq	3f
/*
 * IAMROOT, 2021.09.07:
 * count가 48과 같다면 16byte  2번, 적다면 1번(16byte보단 무조건 많으므로),
 * 많다면 16byte을 3번 복사한다.
 * 이렇게 하면 이제 16바이트 미만의 길이만 남을 것이다.
 */
	cmp	tmp1w, #0x20
	b.eq	1f
	b.lt	2f
	stp	A_l, A_l, [dst], #16
1:
	stp	A_l, A_l, [dst], #16
2:
	stp	A_l, A_l, [dst], #16
/*
 * IAMROOT, 2021.09.07:
 * 16byte 미만만 남았을때, count가 0이면 바로 return 하고 아니면
 * 16byte를 그냥 copy한다. copy할때 dst를 end 주소로 만들어서
 * stp에서 end - 16을 해서 16byte복사를 하는게 보인다. 그전에 복사했던 주소와
 * 몇바이트 겹칠수 있지만 딱히 신경 안쓴다.
e*/
/*
* The last store length is less than 16,use stp to write last 16 bytes.
* It will lead some bytes written twice and the access is non-aligned.
*/
3:
	ands	count, count, #15
	cbz	count, 4f
	add	dst, dst, count
	stp	A_l, A_l, [dst, #-16]	/* Repeat some/all of last store. */
4:
	ret

/*
 * IAMROOT, 2021.09.07:
 * Cache Line크기로 code를 정렬 하였다.
 * .Lnot_short의 코드 자체가 cache line 한줄(64byte)안에 들어가게 해서
 * cache line교체를 막고 2개이상의 cache line을 사용안하게 하기 위함인듯 싶다.
 *
 * 64바이트 이상이면 stp를 통해 16byte씩 copy를 수행하고 그 미만이 되면
 * .Ltail63으로 점프해 나머지를 copy하거나. copy할게 없으면 종료한다.
 */
	/*
	* Critical loop. Start at a new cache line boundary. Assuming
	* 64 bytes per line, this ensures the entire loop is in one line.
	*/
	.p2align	L1_CACHE_SHIFT
.Lnot_short:
	sub	dst, dst, #16/* Pre-bias.  */
	sub	count, count, #64
1:
	stp	A_l, A_l, [dst, #16]
	stp	A_l, A_l, [dst, #32]
	stp	A_l, A_l, [dst, #48]
	stp	A_l, A_l, [dst, #64]!
	subs	count, count, #64
	b.ge	1b
	tst	count, #0x3f
	add	dst, dst, #16
	b.ne	.Ltail63
.Lexitfunc:
	ret

/*
 * IAMROOT, 2021.09.07:
 * 0값으로 64byte보다 큰 길이를 memset 할때 진입한다.
 *
 * - DC Z(Data Cache Zero)
 *   ARMv8-A에서 지원하는 명령이며 64byte의 정렬된 메모리를
 *   64byte단위로 0로 clear할수 있게 한다. 이때 L1, L2캐시 할당을 초래하지 않고
 *   메인 메모리를 clear한다.
 *
 * - dczid_el0 : DC Z의 금지 여부와 한번에 0로 clear할 block size의 값이 존재한다.
 */
	/*
	* For zeroing memory, check to see if we can use the ZVA feature to
	* zero entire 'cache' lines.
	*/
.Lzero_mem:
	cmp	count, #63
	b.le	.Ltail63
	/*
	* For zeroing small amounts of memory, it's not worth setting up
	* the line-clear code.
	*/
	cmp	count, #128
	b.lt	.Lnot_short /*count is at least  128 bytes*/

/*
 * IAMROOT, 2021.09.07:
 * clear할 size가 128바이트 이상일 경우 dczid에서 4번째 bit인 DZP bit를 읽어
 * DC Z수행 여부를 결정한다. DZP bit가 set되있으면 금지상태이므로 not_short으로
 * 점프한다.
 *
 * 그게 아니라면 3번째 bit까지 읽어 64바이트 이상이면 DC Z를 수행 하고 아니면
 * not_short로 그냥 점프한다. 반드시 64바이트 이상이여야 하며 아닌 경우엔
 * 굳이 DC Z를 쓸필요없다는 듯 하다.
 * dczid_el0[0:3]의 zva_len은 block size의 log2 인데 9일때 max가 2048이므로
 *
 * 2048 = 2^11 = 2^(9 + 2) = 4 * 2^9
 *
 * base값인 4를 zva_len값만은 2^(zva_len)한개 지원하는 길이가 된다.
 */
	mrs	tmp1, dczid_el0
	tbnz	tmp1, #4, .Lnot_short
	mov	tmp3w, #4
	and	zva_len, tmp1w, #15	/* Safety: other bits reserved.  */
	lsl	zva_len, tmp3w, zva_len

	ands	tmp3w, zva_len, #63
	/*
	* ensure the zva_len is not less than 64.
	* It is not meaningful to use ZVA if the block size is less than 64.
	*/
	b.ne	.Lnot_short
.Lzero_by_line:
/*
 * IAMROOT, 2021.09.07:
 * DC Z가 수행되는 size보다 남은 size가 작으면 not_short로 점프한다.
 *
 * 그게 아니면 zva_len과 dst가 align이 맞는지를 검사하고,
 *
 * align이 맞다면 바로 수행하기 위해 2f로 넘어가며 (b.eq 2f)
 *
 * 그러지 않을 경우 mask값을 count값에서 빼서 align 이후에도
 * DC Z를 수행할 size가 남았는지를 검사한다.
 */
	/*
	* Compute how far we need to go to become suitably aligned. We're
	* already at quad-word alignment.
	*/
	cmp	count, zva_len_x
	b.lt	.Lnot_short		/* Not enough to reach alignment.  */
	sub	zva_bits_x, zva_len_x, #1
	neg	tmp2, dst
	ands	tmp2, tmp2, zva_bits_x
	b.eq	2f			/* Already aligned.  */
	/* Not aligned, check that there's enough to copy after alignment.*/
	sub	tmp1, count, tmp2
	/*
	* grantee the remain length to be ZVA is bigger than 64,
	* avoid to make the 2f's process over mem range.*/
	cmp	tmp1, #64
	ccmp	tmp1, zva_len_x, #8, ge	/* NZCV=0b1000 */
	b.lt	.Lnot_short
/*
 * IAMROOT, 2021.09.07:
 * 그후 align주소까지 필요한 size(tmp2)만큼 64byte 씩 무조건 copy를 하고
 * size를 넘었으면
 *
 * add	dst, dst, tmp2
 *
 * 에서 넘어간 byte만큼 보정을 해준다. 즉 overwirte가 여기서도 일어날수있지만
 * 신경 안쓰고 아에 보정을 시키는 모습을 보인다.
 */
	/*
	* We know that there's at least 64 bytes to zero and that it's safe
	* to overrun by 64 bytes.
	*/
	mov	count, tmp1
1:
	stp	A_l, A_l, [dst]
	stp	A_l, A_l, [dst, #16]
	stp	A_l, A_l, [dst, #32]
	subs	tmp2, tmp2, #64
	stp	A_l, A_l, [dst, #48]
	add	dst, dst, #64
	b.ge	1b
	/* We've overrun a bit, so adjust dst downwards.*/
	add	dst, dst, tmp2
/*
 * IAMROOT, 2021.09.07:
 * - dc zva : (4 << dczid_el0[0:3])byte만큼을 0로 clear한다.
 *   이때 L1, L2캐시 할당을 초래하지 않고 메인 메모리를 clear한다.
 *
 * - zva_len의 align만큼 clear가 됬으면 나머지값들은 tail_maybe_long에서 처리한다.
 */
2:
	sub	count, count, zva_len_x
3:
	dc	zva, dst
	add	dst, dst, zva_len_x
	subs	count, count, zva_len_x
	b.ge	3b
	ands	count, count, zva_bits_x
	b.ne	.Ltail_maybe_long
	ret
SYM_FUNC_END_PI(memset)
EXPORT_SYMBOL(memset)
SYM_FUNC_END_ALIAS(__memset)
EXPORT_SYMBOL(__memset)
