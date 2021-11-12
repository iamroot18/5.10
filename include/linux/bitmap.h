/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/kernel.h>

/* IAMROOT, 2021.09.30:
 * - bitmap은 기본적으로 unsigned long 타입을 써야된다.
 * - static inline code이기 때문에 가능하면 상수를 써야된다.
 * - DECLARE_BITMAP 매크로를 사용해서 bitmap을 선언해도된다.
 * - bitmap 함수는 굳이 code를 볼필요없이 주석 overview만 봐도 동작을 이해할수있다.
 */
/*
 * bitmaps provide bit arrays that consume one or more unsigned
 * longs.  The bitmap interface and available operations are listed
 * here, in bitmap.h
 *
 * Function implementations generic to all architectures are in
 * lib/bitmap.c.  Functions implementations that are architecture
 * specific are in various include/asm-<arch>/bitops.h headers
 * and other arch/<arch> specific files.
 *
 * See lib/bitmap.c for more details.
 */

/**
 * DOC: bitmap overview
 *
 * The available bitmap operations and their rough meaning in the
 * case that the bitmap is a single unsigned long are thus:
 *
 * The generated code is more efficient when nbits is known at
 * compile-time and at most BITS_PER_LONG.
 *
 * ::
 *
 *  bitmap_zero(dst, nbits)                     *dst = 0UL
 *  bitmap_fill(dst, nbits)                     *dst = ~0UL
 *  bitmap_copy(dst, src, nbits)                *dst = *src
 *  bitmap_and(dst, src1, src2, nbits)          *dst = *src1 & *src2
 *  bitmap_or(dst, src1, src2, nbits)           *dst = *src1 | *src2
 *  bitmap_xor(dst, src1, src2, nbits)          *dst = *src1 ^ *src2
 *  bitmap_andnot(dst, src1, src2, nbits)       *dst = *src1 & ~(*src2)
 *  bitmap_complement(dst, src, nbits)          *dst = ~(*src)
 *  bitmap_equal(src1, src2, nbits)             Are *src1 and *src2 equal?
 *  bitmap_intersects(src1, src2, nbits)        Do *src1 and *src2 overlap?
 *  bitmap_subset(src1, src2, nbits)            Is *src1 a subset of *src2?
 *  bitmap_empty(src, nbits)                    Are all bits zero in *src?
 *  bitmap_full(src, nbits)                     Are all bits set in *src?
 *  bitmap_weight(src, nbits)                   Hamming Weight: number set bits
 *  bitmap_set(dst, pos, nbits)                 Set specified bit area
 *  bitmap_clear(dst, pos, nbits)               Clear specified bit area
 *  bitmap_find_next_zero_area(buf, len, pos, n, mask)  Find bit free area
 *  bitmap_find_next_zero_area_off(buf, len, pos, n, mask, mask_off)  as above
 *  bitmap_next_clear_region(map, &start, &end, nbits)  Find next clear region
 *  bitmap_next_set_region(map, &start, &end, nbits)  Find next set region
 *  bitmap_for_each_clear_region(map, rs, re, start, end)
 *  						Iterate over all clear regions
 *  bitmap_for_each_set_region(map, rs, re, start, end)
 *  						Iterate over all set regions
 *  bitmap_shift_right(dst, src, n, nbits)      *dst = *src >> n
 *  bitmap_shift_left(dst, src, n, nbits)       *dst = *src << n
 *  bitmap_cut(dst, src, first, n, nbits)       Cut n bits from first, copy rest
 *  bitmap_replace(dst, old, new, mask, nbits)  *dst = (*old & ~(*mask)) | (*new & *mask)
 *  bitmap_remap(dst, src, old, new, nbits)     *dst = map(old, new)(src)
 *  bitmap_bitremap(oldbit, old, new, nbits)    newbit = map(old, new)(oldbit)
 *  bitmap_onto(dst, orig, relmap, nbits)       *dst = orig relative to relmap
 *  bitmap_fold(dst, orig, sz, nbits)           dst bits = orig bits mod sz
 *  bitmap_parse(buf, buflen, dst, nbits)       Parse bitmap dst from kernel buf
 *  bitmap_parse_user(ubuf, ulen, dst, nbits)   Parse bitmap dst from user buf
 *  bitmap_parselist(buf, dst, nbits)           Parse bitmap dst from kernel buf
 *  bitmap_parselist_user(buf, dst, nbits)      Parse bitmap dst from user buf
 *  bitmap_find_free_region(bitmap, bits, order)  Find and allocate bit region
 *  bitmap_release_region(bitmap, pos, order)   Free specified bit region
 *  bitmap_allocate_region(bitmap, pos, order)  Allocate specified bit region
 *  bitmap_from_arr32(dst, buf, nbits)          Copy nbits from u32[] buf to dst
 *  bitmap_to_arr32(buf, src, nbits)            Copy nbits from buf to u32[] dst
 *  bitmap_get_value8(map, start)               Get 8bit value from map at start
 *  bitmap_set_value8(map, value, start)        Set 8bit value to map at start
 *
 * Note, bitmap_zero() and bitmap_fill() operate over the region of
 * unsigned longs, that is, bits behind bitmap till the unsigned long
 * boundary will be zeroed or filled as well. Consider to use
 * bitmap_clear() or bitmap_set() to make explicit zeroing or filling
 * respectively.
 */

/**
 * DOC: bitmap bitops
 *
 * Also the following operations in asm/bitops.h apply to bitmaps.::
 *
 *  set_bit(bit, addr)                  *addr |= bit
 *  clear_bit(bit, addr)                *addr &= ~bit
 *  change_bit(bit, addr)               *addr ^= bit
 *  test_bit(bit, addr)                 Is bit set in *addr?
 *  test_and_set_bit(bit, addr)         Set bit and return old value
 *  test_and_clear_bit(bit, addr)       Clear bit and return old value
 *  test_and_change_bit(bit, addr)      Change bit and return old value
 *  find_first_zero_bit(addr, nbits)    Position first zero bit in *addr
 *  find_first_bit(addr, nbits)         Position first set bit in *addr
 *  find_next_zero_bit(addr, nbits, bit)
 *                                      Position next zero bit in *addr >= bit
 *  find_next_bit(addr, nbits, bit)     Position next set bit in *addr >= bit
 *  find_next_and_bit(addr1, addr2, nbits, bit)
 *                                      Same as find_next_bit, but in
 *                                      (*addr1 & *addr2)
 *
 */

/**
 * DOC: declare bitmap
 * The DECLARE_BITMAP(name,bits) macro, in linux/types.h, can be used
 * to declare an array named 'name' of just enough unsigned longs to
 * contain all bit positions from 0 to 'bits' - 1.
 */

/*
 * Allocation and deallocation of bitmap.
 * Provided in lib/bitmap.c to avoid circular dependency.
 */
extern unsigned long *bitmap_alloc(unsigned int nbits, gfp_t flags);
extern unsigned long *bitmap_zalloc(unsigned int nbits, gfp_t flags);
extern void bitmap_free(const unsigned long *bitmap);

/*
 * lib/bitmap.c provides these functions:
 */

extern int __bitmap_empty(const unsigned long *bitmap, unsigned int nbits);
extern int __bitmap_full(const unsigned long *bitmap, unsigned int nbits);
extern int __bitmap_equal(const unsigned long *bitmap1,
			  const unsigned long *bitmap2, unsigned int nbits);
extern bool __pure __bitmap_or_equal(const unsigned long *src1,
				     const unsigned long *src2,
				     const unsigned long *src3,
				     unsigned int nbits);
extern void __bitmap_complement(unsigned long *dst, const unsigned long *src,
			unsigned int nbits);
extern void __bitmap_shift_right(unsigned long *dst, const unsigned long *src,
				unsigned int shift, unsigned int nbits);
extern void __bitmap_shift_left(unsigned long *dst, const unsigned long *src,
				unsigned int shift, unsigned int nbits);
extern void bitmap_cut(unsigned long *dst, const unsigned long *src,
		       unsigned int first, unsigned int cut,
		       unsigned int nbits);
extern int __bitmap_and(unsigned long *dst, const unsigned long *bitmap1,
			const unsigned long *bitmap2, unsigned int nbits);
extern void __bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
			const unsigned long *bitmap2, unsigned int nbits);
extern void __bitmap_xor(unsigned long *dst, const unsigned long *bitmap1,
			const unsigned long *bitmap2, unsigned int nbits);
extern int __bitmap_andnot(unsigned long *dst, const unsigned long *bitmap1,
			const unsigned long *bitmap2, unsigned int nbits);
extern void __bitmap_replace(unsigned long *dst,
			const unsigned long *old, const unsigned long *new,
			const unsigned long *mask, unsigned int nbits);
extern int __bitmap_intersects(const unsigned long *bitmap1,
			const unsigned long *bitmap2, unsigned int nbits);
extern int __bitmap_subset(const unsigned long *bitmap1,
			const unsigned long *bitmap2, unsigned int nbits);
extern int __bitmap_weight(const unsigned long *bitmap, unsigned int nbits);
extern void __bitmap_set(unsigned long *map, unsigned int start, int len);
extern void __bitmap_clear(unsigned long *map, unsigned int start, int len);

extern unsigned long bitmap_find_next_zero_area_off(unsigned long *map,
						    unsigned long size,
						    unsigned long start,
						    unsigned int nr,
						    unsigned long align_mask,
						    unsigned long align_offset);

/**
 * bitmap_find_next_zero_area - find a contiguous aligned zero area
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @align_mask: Alignment mask for zero area
 *
 * The @align_mask should be one less than a power of 2; the effect is that
 * the bit offset of all zero areas this function finds is multiples of that
 * power of 2. A @align_mask of 0 means no alignment is required.
 */
static inline unsigned long
bitmap_find_next_zero_area(unsigned long *map,
			   unsigned long size,
			   unsigned long start,
			   unsigned int nr,
			   unsigned long align_mask)
{
	return bitmap_find_next_zero_area_off(map, size, start, nr,
					      align_mask, 0);
}

extern int bitmap_parse(const char *buf, unsigned int buflen,
			unsigned long *dst, int nbits);
extern int bitmap_parse_user(const char __user *ubuf, unsigned int ulen,
			unsigned long *dst, int nbits);
extern int bitmap_parselist(const char *buf, unsigned long *maskp,
			int nmaskbits);
extern int bitmap_parselist_user(const char __user *ubuf, unsigned int ulen,
			unsigned long *dst, int nbits);
extern void bitmap_remap(unsigned long *dst, const unsigned long *src,
		const unsigned long *old, const unsigned long *new, unsigned int nbits);
extern int bitmap_bitremap(int oldbit,
		const unsigned long *old, const unsigned long *new, int bits);
extern void bitmap_onto(unsigned long *dst, const unsigned long *orig,
		const unsigned long *relmap, unsigned int bits);
extern void bitmap_fold(unsigned long *dst, const unsigned long *orig,
		unsigned int sz, unsigned int nbits);
extern int bitmap_find_free_region(unsigned long *bitmap, unsigned int bits, int order);
extern void bitmap_release_region(unsigned long *bitmap, unsigned int pos, int order);
extern int bitmap_allocate_region(unsigned long *bitmap, unsigned int pos, int order);

#ifdef __BIG_ENDIAN
extern void bitmap_copy_le(unsigned long *dst, const unsigned long *src, unsigned int nbits);
#else
#define bitmap_copy_le bitmap_copy
#endif
extern unsigned int bitmap_ord_to_pos(const unsigned long *bitmap, unsigned int ord, unsigned int nbits);
extern int bitmap_print_to_pagebuf(bool list, char *buf,
				   const unsigned long *maskp, int nmaskbits);

/* IAMROOT, 2021.09.30:
 *
 * - BITMAP_FIRST_WORD_MASK(start)
 *     start bit보다 낮은 bit들은 전부 clear하기 위한것.
 *     ex)
 *     BITMAP_FIRST_WORD_MASK 0  0xffff-ffff-ffff-ffff
 *     BITMAP_FIRST_WORD_MASK 1  0xffff-ffff-ffff-fffe
 *     BITMAP_FIRST_WORD_MASK 2  0xffff-ffff-ffff-fffc
 *     ...
 *     BITMAP_FIRST_WORD_MASK 63 0x8000-0000-0000-0000
 *     BITMAP_FIRST_WORD_MASK 64 0xffff-ffff-ffff-ffff
 *     BITMAP_FIRST_WORD_MASK 65 0xffff-ffff-ffff-fffe
 *
 * - BITMAP_LAST_WORD_MASK(start)
 *     start bit보다 높은 bit들은 전부 clear하기 위한것.
 *     ex)
 *     BITMAP_LAST_WORD_MASK 0  0xffff-ffff-ffff-ffff
 *     BITMAP_LAST_WORD_MASK 1  0x0000-0000-0000-0001
 *     BITMAP_LAST_WORD_MASK 2  0x0000-0000-0000-0003
 *     ...
 *     BITMAP_LAST_WORD_MASK 63 0x7fff-ffff-ffff-ffff
 *     BITMAP_LAST_WORD_MASK 64 0xffff-ffff-ffff-ffff
 *     BITMAP_LAST_WORD_MASK 65 0x0000-0000-0000-0001
 */
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

/*
 * IAMROOT, 2021.11.12:
 * - nbits가 compile-time 상수이고 1 ~ BITS_PER_LONG 사이의 수 (small) 이면 1, 아니면 0.
 *   쉽게 바꿔 말하면, bitmap의 length가 1이다.
 *
 * - __builtin_constant_p: 컴파일 타임에 상수로 정해질 수 있으면 1, 아니면 0.
 *   https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
 */
/*
 * The static inlines below do not handle constant nbits==0 correctly,
 * so make such users (should any ever turn up) call the out-of-line
 * versions.
 */
#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)

/*
 * IAMROOT, 2021.11.12:
 * *dst = 0UL (BITS_TO_LONGS(nbits) 만큼만)
 *
 * - dst[]의 length를 구한다.
 *   dst의 모든 원소를 0으로 초기화.
 */
static inline void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
	unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memset(dst, 0, len);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = ~0UL (BITS_TO_LONGS(nbits) 만큼만)
 *
 * - dst[]의 length를 구한다.
 *   dst의 모든 원소를 0xffff_ffff_...으로 초기화.
 */
static inline void bitmap_fill(unsigned long *dst, unsigned int nbits)
{
	unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memset(dst, 0xff, len);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = *src (BITS_TO_LONGS(nbits) 만큼만)
 *
 * - dst[]의 length를 구한다.
 *   dst의 모든 원소를 src로 복사.
 */
static inline void bitmap_copy(unsigned long *dst, const unsigned long *src,
			unsigned int nbits)
{
	unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memcpy(dst, src, len);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = *src (nbits 만큼만)
 *
 * - dst의 모든 원소를 src로 복사.
 *   nbits가 BITS_PER_LONG로 나누어 떨어지지 않는다면
 *   정확히 nbits만큼을 copy하기 위해서 dst의 마지막 원소에서
 *   nbits를 초과하는 부분은 0으로 초기화 한다.
 */
/*
 * Copy bitmap and clear tail bits in last word.
 */
static inline void bitmap_copy_clear_tail(unsigned long *dst,
		const unsigned long *src, unsigned int nbits)
{
	bitmap_copy(dst, src, nbits);
	if (nbits % BITS_PER_LONG)
		dst[nbits / BITS_PER_LONG] &= BITMAP_LAST_WORD_MASK(nbits);
}

/*
 * On 32-bit systems bitmaps are represented as u32 arrays internally, and
 * therefore conversion is not needed when copying data from/to arrays of u32.
 */
#if BITS_PER_LONG == 64
extern void bitmap_from_arr32(unsigned long *bitmap, const u32 *buf,
							unsigned int nbits);
extern void bitmap_to_arr32(u32 *buf, const unsigned long *bitmap,
							unsigned int nbits);
#else
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
			(const unsigned long *) (buf), (nbits))
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (buf),		\
			(const unsigned long *) (bitmap), (nbits))
#endif

/*
 * IAMROOT, 2021.11.12:
 * *dst = *src1 & *src2 (nbits 만큼만)
 *
 * - nbits가 small이면 (즉, length=1) src1과 src2의 첫번째 원소끼리
 *   and 연산을 한다.
 *   nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값을 dst에 write한다.
 *
 * - nbits가 small이 아니면 __bitmap_and로 forward.
 */
static inline int bitmap_and(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	return __bitmap_and(dst, src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = *src1 | *src2 (nbits 만큼만)
 *
 * - nbits가 small이면 (즉, length=1) src1과 src2의 첫번째 원소끼리
 *   or 연산을 한다.
 *   결과 값을 dst에 write한다.
 *
 * - nbits가 small이 아니면 __bitmap_or로 forward.
 */
static inline void bitmap_or(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src1 | *src2;
	else
		__bitmap_or(dst, src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = *src1 ^ *src2 (nbits 만큼만)
 *
 * - nbits가 small이면 (즉, length=1) src1과 src2의 첫번째 원소끼리
 *   xor 연산을 한다.
 *   결과 값을 dst에 write한다.
 *
 * - nbits가 small이 아니면 __bitmap_xor로 forward.
 */
static inline void bitmap_xor(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src1 ^ *src2;
	else
		__bitmap_xor(dst, src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = *src1 & ~(*src2) (nbits 만큼만)
 *
 * - nbits가 small이면 (즉, length=1) src1과 src2의 첫번째 원소끼리
 *   andnot 연산을 하고 (src1 & ~src2) nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값을 dst에 write한다.
 *
 * - nbits가 small이 아니면 __bitmap_andnot로 forward.
 */
static inline int bitmap_andnot(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return (*dst = *src1 & ~(*src2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	return __bitmap_andnot(dst, src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * *dst = ~(*src) (nbits 만큼만)
 *
 * - nbits가 small이면 (즉, length=1) src의 첫번째 원소의 bit를 flip한다.
 *   결과 값을 dst에 write한다.
 *
 * - nbits가 small이 아니면 __bitmap_complement로 forward.
 */
static inline void bitmap_complement(unsigned long *dst, const unsigned long *src,
			unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = ~(*src);
	else
		__bitmap_complement(dst, src, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 *
 * - 전제 조건으로, 커널에서 0xffffffff00000000와 같이 msb(왼쪽)부터
 *   bitmap의 bit를 채우지 않는다. lsb(오른쪽)부터 bit가 차게 된다.
 *   (0x00000000ffffffff)
 *
 * - Endian에 따라 BITMAP_MEM_ALIGNMENT의 값이 달라지는 이유는
 *   아래의 예제를 통해 생각해 볼 수 있다.
 *
 * - unsigned long s1[] = {0xffffffffffffffff, 0xffffffffffffffff};
 *   unsigned long s2[] = {0xffffffffffffffff, 0x00000000ffffffff};
 *   printf("%x\n", memcmp(s1, s2, 9));
 *
 * - little-endian cpu에서는 s1과 s2의 9바이트 값을 비교하였을 때
 *   값이 같다(=0)고 나온다. unsigned long 안의 byte 순서가 역전되기
 *   때문이다.
 *
 * - big-endian cpu에서는 s1과 s2의 9바이트 값을 비교하였을 때
 *   값이 같지 않다(!= 0)고 나온다. unsigned long 안의 byte 순서가
 *   역전되지 않기 때문이다.
 *
 * - 따라서, big-endian cpu에서는 bitmap 2개를 서로 비교할 때
 *   nbits가 unsigned long의 bit수(32 or 64)로 나누어 떨어지지 않으면
 *   mem_xxx 함수를 쓰지 않는다. 근본적인 이유는 bitmap에서 bit가
 *   msb(오른쪽)에서부터 차기 때문이다.
 *
 * - 따라서 big-endian cpu인 경우에는 BITMAP_MEM_ALIGNMENT 값이
 *   아키텍처에 따라 32 or 64가 된다. 이를 풀어서 말하면, nbits가
 *   unsigned long의 bit수로 나누어 떨어지는 경우에만 mem_xxx함수를
 *   사용하겠다는 의미이다. (IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
 *
 * - little-endian cpu인 경우에 BITMAP_MEM_ALIGNMENT 값이 8인 이유는
 *   nbits가 8로 나누어 떨어지기만 하면 위의 사례에서 보았던 것 처럼
 *   mem_xxx함수를 사용할 수 있기 때문이다.
 */
#ifdef __LITTLE_ENDIAN
#define BITMAP_MEM_ALIGNMENT 8
#else
#define BITMAP_MEM_ALIGNMENT (8 * sizeof(unsigned long))
#endif
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

/*
 * IAMROOT, 2021.11.12:
 * src1과 src2가 같은지 알아온다. (nbits 만큼만 비교)
 *
 * - nbits가 small이면 (즉, length=1) src1, src2의 첫번째 원소끼리
 *   eor 연산을 한다.
 *   nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값이 0이라면 (equal) 1을 return, non-zero라면 0을 return한다.
 *
 * - nbits가 small이 아니라면 memcmp를 사용하여 둘을 비교하는데
 *   단, little_endian인 경우에는 nbits가 8로 나누어 떨어진다면,
 *   big_endian인 경우에는 unsigned long의 bit수(32 or 64)로
 *   나누어 떨어진다면 memcmp함수를 사용하여 src1, src2를 비교한다.
 *
 * - 그 외의 경우에는 __bitmap_equal에 forward한다.
 */
static inline int bitmap_equal(const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return !((*src1 ^ *src2) & BITMAP_LAST_WORD_MASK(nbits));
	if (__builtin_constant_p(nbits & BITMAP_MEM_MASK) &&
	    IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
		return !memcmp(src1, src2, nbits / 8);
	return __bitmap_equal(src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * src1과 src2를 or한 결과가 src3랑 같은지 알아온다.
 * (nbits 만큼만 비교)
 *
 * - nbits가 small이 아니라면 __bitmap_or_equal에 forward한다.
 *
 * - nbits가 small이라면 (length=1) src1과 src2를 or 연산하고
 *   결과 값을 src3와 eor 연산을 한다.
 *   nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값이 0이라면 (equal) 1을 return, non-zero라면 0을 return한다.
 */
/**
 * bitmap_or_equal - Check whether the or of two bitmaps is equal to a third
 * @src1:	Pointer to bitmap 1
 * @src2:	Pointer to bitmap 2 will be or'ed with bitmap 1
 * @src3:	Pointer to bitmap 3. Compare to the result of *@src1 | *@src2
 * @nbits:	number of bits in each of these bitmaps
 *
 * Returns: True if (*@src1 | *@src2) == *@src3, false otherwise
 */
static inline bool bitmap_or_equal(const unsigned long *src1,
				   const unsigned long *src2,
				   const unsigned long *src3,
				   unsigned int nbits)
{
	if (!small_const_nbits(nbits))
		return __bitmap_or_equal(src1, src2, src3, nbits);

	return !(((*src1 | *src2) ^ *src3) & BITMAP_LAST_WORD_MASK(nbits));
}

/*
 * IAMROOT, 2021.11.12:
 * src1과 src2에 겹치는 부분(intersection)이 있는지 알아온다.
 * (nbits 만큼만 비교)
 *
 * - nbits가 small이라면 (length=1) src1과 src2를 and 연산한다.
 *   nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값이 non-zero라면 1을 return, 0라면 0을 return한다.
 *
 * - nbits가 small이 아니라면 __bitmap_intersects에 forward한다.
 */
static inline int bitmap_intersects(const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return ((*src1 & *src2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	else
		return __bitmap_intersects(src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * src1이 src2의 subset인지 알아온다. (nbits만큼만 비교)
 *
 * - nbits가 small이라면 (length=1) src1과 ~src2를 and 연산한다.
 *   (src1 - src2)
 *   nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값이 0이라면 1을 return (src1은 src2의 subset),
 *   non-zero라면 0을 return한다.
 *
 * - nbits가 small이 아니라면 __bitmap_subset에 forward한다.
 */
static inline int bitmap_subset(const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return ! ((*src1 & ~(*src2)) & BITMAP_LAST_WORD_MASK(nbits));
	else
		return __bitmap_subset(src1, src2, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * src에서 nbits 만큼의 비트가 전부 0인지 알아온다.
 *
 * - nbits가 small이라면 (length=1)
 *   src에서 nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값이 0이라면 1을 return (src는 empty),
 *   non-zero라면 0을 return한다.
 *
 * - nbits가 small이 아니라면 find_first_bit로
 *   nbits안에 1이 있는지 검사한다.
 *   src가 empty라면 find_first_bit는 nbits를 return한다.
 */
static inline int bitmap_empty(const unsigned long *src, unsigned nbits)
{
	if (small_const_nbits(nbits))
		return ! (*src & BITMAP_LAST_WORD_MASK(nbits));

	return find_first_bit(src, nbits) == nbits;
}

/*
 * IAMROOT, 2021.11.12:
 * src에서 nbits 만큼의 비트가 전부 1인지 알아온다.
 *
 * - nbits가 small이라면 (length=1)
 *   src의 bit를 flip한 후 nbits를 초과하는 부분은 0으로 초기화한다.
 *   결과 값이 0이라면 1을 return (src는 full),
 *   non-zero라면 0을 return한다.
 *
 * - nbits가 small이 아니라면 find_first_zero_bit로
 *   nbits안에 0이 있는지 검사한다.
 *   src가 full이라면 find_first_zero_bit는 nbits를 return한다.
 */
static inline int bitmap_full(const unsigned long *src, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return ! (~(*src) & BITMAP_LAST_WORD_MASK(nbits));

	return find_first_zero_bit(src, nbits) == nbits;
}

/*
 * IAMROOT, 2021.11.09:
 * src에서 nbits 만큼의 비트에서 1로 설정된 비트 수를 알아온다.
 *
 * - nbits가 small이라면 (length=1)
 *   src에서 nbits를 초과하는 부분은 0으로 초기화한 후
 *   hweight_long에 forward한다.
 *
 * - nbits가 small이 아니라면 __bitmap_weight에 forward한다.
 */
static __always_inline int bitmap_weight(const unsigned long *src, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return hweight_long(*src & BITMAP_LAST_WORD_MASK(nbits));
	return __bitmap_weight(src, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * map에서 start부터 nbits만큼의 bit를 set한다.
 *
 * - nbits가 1이면 __set_bit로 해당 start bit만 set한다.
 *
 * - start와 nbits 모두 BITMAP_MEM_ALIGNMENT에 align되있으면
 *   memset으로 해당 영역을 set한다.
 *
 * - 그 외의 경우는 __bitmap_set에 forward한다.
 */
static __always_inline void bitmap_set(unsigned long *map, unsigned int start,
		unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && nbits == 1)
		__set_bit(start, map);
	else if (__builtin_constant_p(start & BITMAP_MEM_MASK) &&
		 IS_ALIGNED(start, BITMAP_MEM_ALIGNMENT) &&
		 __builtin_constant_p(nbits & BITMAP_MEM_MASK) &&
		 IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
		memset((char *)map + start / 8, 0xff, nbits / 8);
	else
		__bitmap_set(map, start, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * map에서 start부터 nbits만큼의 bit를 clear한다.
 *
 * - nbits가 1이면 __clear_bit로 해당 start bit만 clear한다.
 *
 * - start와 nbits 모두 BITMAP_MEM_ALIGNMENT에 align되있으면
 *   memset으로 해당 영역을 clear한다.
 *
 * - 그 외의 경우는 __bitmap_clear에 forward한다.
 */
static __always_inline void bitmap_clear(unsigned long *map, unsigned int start,
		unsigned int nbits)
{
	if (__builtin_constant_p(nbits) && nbits == 1)
		__clear_bit(start, map);
	else if (__builtin_constant_p(start & BITMAP_MEM_MASK) &&
		 IS_ALIGNED(start, BITMAP_MEM_ALIGNMENT) &&
		 __builtin_constant_p(nbits & BITMAP_MEM_MASK) &&
		 IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
		memset((char *)map + start / 8, 0, nbits / 8);
	else
		__bitmap_clear(map, start, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * src에서 nbits만큼을 right shift한다.
 *
 * - nbits가 small이라면 (length=1)
 *   src에서 nbits를 초과하는 부분은 0으로 초기화한 후
 *   오른쪽으로 shift만큼 shift시킨 후
 *   dst에 write한다.
 *
 * - 그 외의 경우는 __bitmap_shift_right에 forward한다.
 */
static inline void bitmap_shift_right(unsigned long *dst, const unsigned long *src,
				unsigned int shift, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = (*src & BITMAP_LAST_WORD_MASK(nbits)) >> shift;
	else
		__bitmap_shift_right(dst, src, shift, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * src에서 nbits만큼을 left shift한다.
 *
 * - nbits가 small이라면 (length=1)
 *   왼쪽으로 shift만큼 shift시킨 후
 *   src에서 nbits를 초과하는 부분은 0으로 초기화한 후
 *   dst에 write한다. 
 *
 * - 그 외의 경우는 __bitmap_shift_left에 forward한다.
 */
static inline void bitmap_shift_left(unsigned long *dst, const unsigned long *src,
				unsigned int shift, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = (*src << shift) & BITMAP_LAST_WORD_MASK(nbits);
	else
		__bitmap_shift_left(dst, src, shift, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * old에서 mask부분을 new로 replace한다.
 * (length=BITS_TO_LONGS(nbits))
 *
 * - nbits가 small이라면 (length=1)
 *   old에서 mask가 아닌 부분과
 *   new에서 mask인 부분을 or 연산한 값을
 *   dst에 write한다.
 *
 * - 그 외의 경우는 __bitmap_replace에 forward한다.
 */
static inline void bitmap_replace(unsigned long *dst,
				  const unsigned long *old,
				  const unsigned long *new,
				  const unsigned long *mask,
				  unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = (*old & ~(*mask)) | (*new & *mask);
	else
		__bitmap_replace(dst, old, new, mask, nbits);
}

/*
 * IAMROOT, 2021.11.12:
 * end부터 0이 처음 나오는 부분을 rs,
 * rs 이후로 1이 처음 나오는 부분을 re에 write한다.
 *
 * - 용어 줄임말
 *   rs: region start
 *   re: region end
 *   (추측)
 *
 * - 인자
 *   rs: searching을 시작할 start index.
 */
static inline void bitmap_next_clear_region(unsigned long *bitmap,
					    unsigned int *rs, unsigned int *re,
					    unsigned int end)
{
	*rs = find_next_zero_bit(bitmap, end, *rs);
	*re = find_next_bit(bitmap, end, *rs + 1);
}

/*
 * IAMROOT, 2021.11.12:
 * end부터 1이 처음 나오는 부분을 rs,
 * rs 이후로 0이 처음 나오는 부분을 re에 write한다.

 * - 인자
 *   rs: searching을 시작할 start index.
 */
static inline void bitmap_next_set_region(unsigned long *bitmap,
					  unsigned int *rs, unsigned int *re,
					  unsigned int end)
{
	*rs = find_next_bit(bitmap, end, *rs);
	*re = find_next_zero_bit(bitmap, end, *rs + 1);
}

/*
 * Bitmap region iterators.  Iterates over the bitmap between [@start, @end).
 * @rs and @re should be integer variables and will be set to start and end
 * index of the current clear or set region.
 */
#define bitmap_for_each_clear_region(bitmap, rs, re, start, end)	     \
	for ((rs) = (start),						     \
	     bitmap_next_clear_region((bitmap), &(rs), &(re), (end));	     \
	     (rs) < (re);						     \
	     (rs) = (re) + 1,						     \
	     bitmap_next_clear_region((bitmap), &(rs), &(re), (end)))

#define bitmap_for_each_set_region(bitmap, rs, re, start, end)		     \
	for ((rs) = (start),						     \
	     bitmap_next_set_region((bitmap), &(rs), &(re), (end));	     \
	     (rs) < (re);						     \
	     (rs) = (re) + 1,						     \
	     bitmap_next_set_region((bitmap), &(rs), &(re), (end)))

/**
 * BITMAP_FROM_U64() - Represent u64 value in the format suitable for bitmap.
 * @n: u64 value
 *
 * Linux bitmaps are internally arrays of unsigned longs, i.e. 32-bit
 * integers in 32-bit environment, and 64-bit integers in 64-bit one.
 *
 * There are four combinations of endianness and length of the word in linux
 * ABIs: LE64, BE64, LE32 and BE32.
 *
 * On 64-bit kernels 64-bit LE and BE numbers are naturally ordered in
 * bitmaps and therefore don't require any special handling.
 *
 * On 32-bit kernels 32-bit LE ABI orders lo word of 64-bit number in memory
 * prior to hi, and 32-bit BE orders hi word prior to lo. The bitmap on the
 * other hand is represented as an array of 32-bit words and the position of
 * bit N may therefore be calculated as: word #(N/32) and bit #(N%32) in that
 * word.  For example, bit #42 is located at 10th position of 2nd word.
 * It matches 32-bit LE ABI, and we can simply let the compiler store 64-bit
 * values in memory as it usually does. But for BE we need to swap hi and lo
 * words manually.
 *
 * With all that, the macro BITMAP_FROM_U64() does explicit reordering of hi and
 * lo parts of u64.  For LE32 it does nothing, and for BE environment it swaps
 * hi and lo words, as is expected by bitmap.
 */
#if __BITS_PER_LONG == 64
#define BITMAP_FROM_U64(n) (n)
#else
#define BITMAP_FROM_U64(n) ((unsigned long) ((u64)(n) & ULONG_MAX)), \
				((unsigned long) ((u64)(n) >> 32))
#endif

/**
 * bitmap_from_u64 - Check and swap words within u64.
 *  @mask: source bitmap
 *  @dst:  destination bitmap
 *
 * In 32-bit Big Endian kernel, when using ``(u32 *)(&val)[*]``
 * to read u64 mask, we will get the wrong word.
 * That is ``(u32 *)(&val)[0]`` gets the upper 32 bits,
 * but we expect the lower 32-bits of u64.
 */
static inline void bitmap_from_u64(unsigned long *dst, u64 mask)
{
	dst[0] = mask & ULONG_MAX;

	if (sizeof(mask) > sizeof(unsigned long))
		dst[1] = mask >> 32;
}

/**
 * bitmap_get_value8 - get an 8-bit value within a memory region
 * @map: address to the bitmap memory region
 * @start: bit offset of the 8-bit value; must be a multiple of 8
 *
 * Returns the 8-bit value located at the @start bit offset within the @src
 * memory region.
 */
static inline unsigned long bitmap_get_value8(const unsigned long *map,
					      unsigned long start)
{
	const size_t index = BIT_WORD(start);
	const unsigned long offset = start % BITS_PER_LONG;

	return (map[index] >> offset) & 0xFF;
}

/**
 * bitmap_set_value8 - set an 8-bit value within a memory region
 * @map: address to the bitmap memory region
 * @value: the 8-bit value; values wider than 8 bits may clobber bitmap
 * @start: bit offset of the 8-bit value; must be a multiple of 8
 */
static inline void bitmap_set_value8(unsigned long *map, unsigned long value,
				     unsigned long start)
{
	const size_t index = BIT_WORD(start);
	const unsigned long offset = start % BITS_PER_LONG;

	map[index] &= ~(0xFFUL << offset);
	map[index] |= value << offset;
}

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_BITMAP_H */
