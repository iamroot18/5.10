/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Cache maintenance
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/errno.h>
#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/assembler.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>
#include <asm/asm-uaccess.h>

/*
 *	flush_icache_range(start,end)
 *
 *	Ensure that the I and D caches are coherent within specified region.
 *	This is typically used when code has been written to a memory region,
 *	and will be executed.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(__flush_icache_range)
	/* FALLTHROUGH */

/*
 *	__flush_cache_user_range(start,end)
 *
 *	Ensure that the I and D caches are coherent within specified region.
 *	This is typically used when code has been written to a memory region,
 *	and will be executed.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(__flush_cache_user_range)
	uaccess_ttbr0_enable x2, x3, x4
alternative_if ARM64_HAS_CACHE_IDC
	dsb	ishst
	b	7f
alternative_else_nop_endif
	dcache_line_size x2, x3
	sub	x3, x2, #1
	bic	x4, x0, x3
1:
user_alt 9f, "dc cvau, x4",  "dc civac, x4",  ARM64_WORKAROUND_CLEAN_CACHE
	add	x4, x4, x2
	cmp	x4, x1
	b.lo	1b
	dsb	ish

7:
alternative_if ARM64_HAS_CACHE_DIC
	isb
	b	8f
alternative_else_nop_endif
	invalidate_icache_by_line x0, x1, x2, x3, 9f
8:	mov	x0, #0
1:
	uaccess_ttbr0_disable x1, x2
	ret
9:
	mov	x0, #-EFAULT
	b	1b
SYM_FUNC_END(__flush_icache_range)
SYM_FUNC_END(__flush_cache_user_range)

/*
 *	invalidate_icache_range(start,end)
 *
 *	Ensure that the I cache is invalid within specified region.
 *
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
SYM_FUNC_START(invalidate_icache_range)
alternative_if ARM64_HAS_CACHE_DIC
	mov	x0, xzr
	isb
	ret
alternative_else_nop_endif

	uaccess_ttbr0_enable x2, x3, x4

	invalidate_icache_by_line x0, x1, x2, x3, 2f
	mov	x0, xzr
1:
	uaccess_ttbr0_disable x1, x2
	ret
2:
	mov	x0, #-EFAULT
	b	1b
SYM_FUNC_END(invalidate_icache_range)

/*
 *	__flush_dcache_area(kaddr, size)
 *
 *	Ensure that any D-cache lines for the interval [kaddr, kaddr+size)
 *	are cleaned and invalidated to the PoC.
 *
 *	- kaddr   - kernel address
 *	- size    - size in question
 */
SYM_FUNC_START_PI(__flush_dcache_area)
	dcache_by_line_op civac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END_PI(__flush_dcache_area)

/*
 *	__clean_dcache_area_pou(kaddr, size)
 *
 * 	Ensure that any D-cache lines for the interval [kaddr, kaddr+size)
 * 	are cleaned to the PoU.
 *
 *	- kaddr   - kernel address
 *	- size    - size in question
 */
SYM_FUNC_START(__clean_dcache_area_pou)
alternative_if ARM64_HAS_CACHE_IDC
	dsb	ishst
	ret
alternative_else_nop_endif
	dcache_by_line_op cvau, ish, x0, x1, x2, x3
	ret
SYM_FUNC_END(__clean_dcache_area_pou)

/*
 *	__inval_dcache_area(kaddr, size)
 *
 * 	Ensure that any D-cache lines for the interval [kaddr, kaddr+size)
 * 	are invalidated. Any partial lines at the ends of the interval are
 *	also cleaned to PoC to prevent data loss.
 *
 *	- kaddr   - kernel address
 *	- size    - size in question
 */
SYM_FUNC_START_LOCAL(__dma_inv_area)

/*
 * IAMROOT, 2021.07.17: 
 *
 * - SYM_FUNC_START_PI(x) 해석:
 *   - SYM_FUNC_START_ALIAS(__pi_##x): 하나의 FUNC에 1개 이상의 이름을
 *                                     부여하고 싶을때 사용하는 매크로
 *          .globl __pi___inval_dcache_area
 *          .align 2;
 *          __pi___inval_dcache_area:
 *
 *   - SYM_FUNC_START()
 *          .globl __inval_dcache_area
 *          .align 2;
 *          __inval_dcache_area:
 *
 *   - BTI_C
 *          hint 34;
 */
SYM_FUNC_START_PI(__inval_dcache_area)
	/* FALLTHROUGH */

/*
 *	__dma_inv_area(start, size)
 *	- start   - virtual start address of region
 *	- size    - size in question
 */
 /*
  * IAMROOT, 2021.07.18: 
  * __inval_dcache_area(char * start, int size) {
  *	  int end = start + size;
  *	  int dcache_min_line = dcache_line_size();	// 64로가정 0x40
  *	  int mask = dcache_min_line - 1;		// 0x40 - 1 = 0x3f
  *	  if(end & mark) {
  *      	end &= ~(mark);
  *      	clean_invalidated_cache(end); // dc civac, x1
  *        } 
  *        
  *        if(start & mark) {
  *        	  start &= ~(mark);
  *        	  clean_invalidated_cache(start);
  *        	  start += dcache_min_line;
  *        }
  *
  *        while(start < end) {
  *      	invalidated_cache(start);
  *      	start += dcache_min_line;
  *        }
  *  }
  */

	add	x1, x1, x0
	dcache_line_size x2, x3

/* IAMROOT, 2021.07.17: 
 * End line aligned를 체크하기 위해서 수행하는 인스트럭션
 * 인스트럭션 결과로 모든 Bit가 Set
 */
	sub	x3, x2, #1

/* IAMROOT, 2021.07.17: 
 * tst r0, r1 : r0와 r1을 AND 연산한 것처럼 
 * -> CPSR 의 NZCV Flag가 결정 
 * -> Z가 영향을 받음
 */
	tst	x1, x3				// end cache line aligned?

/* IAMROOT, 2021.07.17: 
 * bic r0, r1, r2 : r1 & ~r2 의 결과에서 1을 다 Clear한 후 r0에 저장
 */
	bic	x1, x1, x3

/* IAMROOT, 2021.07.17: 
 * b.eq : 위의 tst 명령어로 인해서 Z flag = 1 이라면 1f 실행 
 * 1f: 밑의 Label 1을 의미
 */	
	b.eq	1f

/* IAMROOT, 2021.07.17: 
 * D : Data cache
 * U : Unified cache
 * dc : 통합 캐시까지 모두 Clear
 * Clean : Dirty bit가 marking된 cache line에 한하여
 *         next level cache (unified L2) or main memory에
 *         writing 후 dirty bit clear 수행.
 *         (write-back policy 일때 적용되는 규칙)
 * Invalidate : Cache line의 V Status를 Clear
 *
 * - Point of Coherency 의미 (SMP system)
 *   For a particular address, the PoC is the point at which all
 *   observers, for example, cores, DSPs, or DMA engines,
 *   that can access memory, are guaranteed to see the same copy of a memory
 *   location. Typically, this is the main external system memory.
 */
	dc	civac, x1			// clean & invalidate D / U line

1:	tst	x0, x3				// start cache line aligned?
	bic	x0, x0, x3
	b.eq	2f
	dc	civac, x0			// clean & invalidate D / U line
	b	3f
2:	dc	ivac, x0			// invalidate D / U line
3:	add	x0, x0, x2
	cmp	x0, x1
	b.lo	2b
	dsb	sy
	ret
SYM_FUNC_END_PI(__inval_dcache_area)
SYM_FUNC_END(__dma_inv_area)

/*
 *	__clean_dcache_area_poc(kaddr, size)
 *
 * 	Ensure that any D-cache lines for the interval [kaddr, kaddr+size)
 * 	are cleaned to the PoC.
 *
 *	- kaddr   - kernel address
 *	- size    - size in question
 */
SYM_FUNC_START_LOCAL(__dma_clean_area)
SYM_FUNC_START_PI(__clean_dcache_area_poc)
	/* FALLTHROUGH */

/*
 *	__dma_clean_area(start, size)
 *	- start   - virtual start address of region
 *	- size    - size in question
 */
	dcache_by_line_op cvac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END_PI(__clean_dcache_area_poc)
SYM_FUNC_END(__dma_clean_area)

/*
 *	__clean_dcache_area_pop(kaddr, size)
 *
 * 	Ensure that any D-cache lines for the interval [kaddr, kaddr+size)
 * 	are cleaned to the PoP.
 *
 *	- kaddr   - kernel address
 *	- size    - size in question
 */
SYM_FUNC_START_PI(__clean_dcache_area_pop)
	alternative_if_not ARM64_HAS_DCPOP
	b	__clean_dcache_area_poc
	alternative_else_nop_endif
	dcache_by_line_op cvap, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END_PI(__clean_dcache_area_pop)

/*
 *	__dma_flush_area(start, size)
 *
 *	clean & invalidate D / U line
 *
 *	- start   - virtual start address of region
 *	- size    - size in question
 */
SYM_FUNC_START_PI(__dma_flush_area)
	dcache_by_line_op civac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END_PI(__dma_flush_area)

/*
 *	__dma_map_area(start, size, dir)
 *	- start	- kernel virtual start address
 *	- size	- size of region
 *	- dir	- DMA direction
 */
SYM_FUNC_START_PI(__dma_map_area)
	cmp	w2, #DMA_FROM_DEVICE
	b.eq	__dma_inv_area
	b	__dma_clean_area
SYM_FUNC_END_PI(__dma_map_area)

/*
 *	__dma_unmap_area(start, size, dir)
 *	- start	- kernel virtual start address
 *	- size	- size of region
 *	- dir	- DMA direction
 */
SYM_FUNC_START_PI(__dma_unmap_area)
	cmp	w2, #DMA_TO_DEVICE
	b.ne	__dma_inv_area
	ret
SYM_FUNC_END_PI(__dma_unmap_area)
