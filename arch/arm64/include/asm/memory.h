/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/memory.h
 *
 * Copyright (C) 2000-2002 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * Note: this file should not be included by non-asm/.h files
 */
#ifndef __ASM_MEMORY_H
#define __ASM_MEMORY_H

#include <linux/const.h>
#include <linux/sizes.h>
#include <asm/page-def.h>

/*
 * Size of the PCI I/O space. This must remain a power of two so that
 * IO_SPACE_LIMIT acts as a mask for the low bits of I/O addresses.
 */
#define PCI_IO_SIZE		SZ_16M
/*
 * IAMROOT, 2021.09.04:
 * page 구조체가 mapping 되는 공간. 전체 kernel의 가상주소공간이
 * mapping 됬을때의 필요한 공간이 몇인지를 계산.
 *
 * - PAGE_END : 0xffff_8000_0000_0000
 * - PAGE_OFFSET : 0xffff_0000_0000_0000
 * - STRUCT_PAGE_MAX_SHIFT : 6(default 값. debug등의 값이 더 존재하면 7).
 *
 * 0xffff_8000_0000_0000 - 0xffff_0000_0000_0000 = 0x8000_0000_0000
 *
 * 0x8000_0000_0000 >> (12 - 6) = 0x200_0000_0000 = VMEMMAP_SIZE
 *
 * 즉 VMEMMAP_SIZE = 2TB
*/

/*
 * VMEMMAP_SIZE - allows the whole linear region to be covered by
 *                a struct page array
 *
 * If we are configured with a 52-bit kernel VA then our VMEMMAP_SIZE
 * needs to cover the memory region from the beginning of the 52-bit
 * PAGE_OFFSET all the way to PAGE_END for 48-bit. This allows us to
 * keep a constant PAGE_OFFSET and "fallback" to using the higher end
 * of the VMEMMAP where 52-bit support is not available in hardware.
 */
#define VMEMMAP_SIZE ((_PAGE_END(VA_BITS_MIN) - PAGE_OFFSET) \
			>> (PAGE_SHIFT - STRUCT_PAGE_MAX_SHIFT))

/*
 * PAGE_OFFSET - the virtual address of the start of the linear map, at the
 *               start of the TTBR1 address space.
 * PAGE_END - the end of the linear map, where all other kernel mappings begin.
 * KIMAGE_VADDR - the virtual address of the start of the kernel image.
 * VA_BITS - the maximum number of bits for virtual addresses.
 */
/*
 * IAMROOT, 2021.08.21: 
 *-------------------------------------------------------------------------
 *   Kernel 가상 주소 공간 Mapping (VA 48bit 기준)
 * ======+=======================+=======================+===================
 * all   | virtual address       | 해당 주소의           |
 * size  |                       | source상의            | size
 *       |                       | 정의                  |
 * ======+=======================+=======================+===================
 * 128TB | 0xffff_ffff_ffff_ffff |
 *       +-----------------------+-----------------------+-------------------
 *       |                        SZ_2M(0x20_0000)
 *       +-----------------------+-----------------------+-------------------
 *       | 0xffff_ffff_ffe0_0000 | VMEMMAP_END           |
 *       +-----------------------+                       |
 *       |                       | VMEMMAP_SIZE          | 2TB 
 *       +-----------------------+                       |
 *       | 0xffff_fdff_ffe0_0000 | VMEMMAP_START         |
 *       +-----------------------+-----------------------+-------------------
 *       |                        SZ_2M(0x20_0000)
 *       +-----------------------+-----------------------+------------------
 *       | 0xffff_fdff_ffc0_0000 | PCI_IO_END            |
 *       +-----------------------+                       |
 *       |                       | PCI_IO_SIZE           | SZ_16M(0x100_0000)
 *       +-----------------------+                       |
 *       | 0xffff_fdff_ec00_0000 | PCI_IO_START          |
 *       +-----------------------+-----------------------+------------------
 *       |                        SZ_2M(0x20_0000)
 *       +-----------------------+-----------------------+------------------
 *       | 0xffff_fdff_ea00_0000 | FIXADDR_TOP           |
 *       +-----------------------+                       |
 *       |                       | FIXADDR_SIZE          | 4MB(0x40_000) ~ 약 6MB
 *       +-----------------------+                       | CONFIG에 따라 달라짐
 *       | 0xffff_fdff_e9c0_0000 | FIXADDR_START         | fixed_addresses 참고
 *       |         ~             |                       |
 *       | 0xffff_fdff_e9a0_0000 |                       |
 *       +-----------------------+-----------------------+--------+---------
 *       |      ~~~~~            |                       |      vmlloc      
 *       +-----------------------+-----------------------+--------+ 
 *       |                       | (vmlinux.lds.S참고)   |        | 
 *       |                       | _end                  |        |
 *       |                       | (vmlinux.lds.S참고)   |        |
 *       |                       | RO_DATA               |        |
 *       |                       | _etext                |        |
 *       |                       | _stex의 text들        |        |
 *       |                       | _stext                |        |
 *       |-----------------------+                       | kernel |
 *       | 0xffff_8000_1000_0000 | HEAD_TEXT             | image  |
 *       |                       | _text                 |        |
 *       |                       | KIMAGE_VADDR          |        |
 *       |                       | runtime에 randomize가 |        |
 *       |                       | 들어갈수있다.         |        |
 *       |                       +-----------------------+--------+---------
 *       |                       | MODULES_END           |
 *       +-----------------------+                       |
 *       |                       | MODULES_VSIZE         | SZ_128M
 *       +-----------------------+                       | (0x800_0000)
 *       | 0xffff_8000_0800_0000 | MODULES_VADDR         |
 *       |                       +-----------------------+------------------
 *       |                       | BPF_JIT_REGION_END    |
 *       +-----------------------+                       |
 *       |                       | BPF_JIT_REGION_SIZE   | SZ_128M
 *-------+-----------------------+                       | (0x800_0000)
 * 128TB | 0xffff_8000_0000_0000 | BPF_JIT_REGION_START  |
 *       |                       +-----------------------+-------------------
 *       |                       | KASAN_SHADOW_END      |
 *       |                       +-----------------------+
 *       |                       | PAGE_END              |
 *       +-----------------------+
 *       |
 *       | ~~~~~~~~~~~~
 *       |
 *       +-----------------------+
 *       | 0xffff_0000_0000_0000 | PAGE_OFFSET           |
 *-------+-----------------------+-----------------------+-------------------
 */  
#define VA_BITS			(CONFIG_ARM64_VA_BITS)
#define _PAGE_OFFSET(va)	(-(UL(1) << (va)))
/*
 * IAMROOT, 2021.09.04:
 * - VA 48Bit 4kb page 일때 : 0xffff_0000_0000_0000
 */
#define PAGE_OFFSET		(_PAGE_OFFSET(VA_BITS))
#define KIMAGE_VADDR		(MODULES_END)
#define BPF_JIT_REGION_START	(KASAN_SHADOW_END)
#define BPF_JIT_REGION_SIZE	(SZ_128M)
#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
#define MODULES_END		(MODULES_VADDR + MODULES_VSIZE)
#define MODULES_VADDR		(BPF_JIT_REGION_END)
#define MODULES_VSIZE		(SZ_128M)
/*
 * IAMROOT, 2021.09.04:
 * -
 *  (0 - 0x200_0000_0000 - 0x20_0000) = 0xffff_fdff_feff_ffff
 **/
#define VMEMMAP_START		(-VMEMMAP_SIZE - SZ_2M)
#define VMEMMAP_END		(VMEMMAP_START + VMEMMAP_SIZE)
#define PCI_IO_END		(VMEMMAP_START - SZ_2M)
#define PCI_IO_START		(PCI_IO_END - PCI_IO_SIZE)
#define FIXADDR_TOP		(PCI_IO_START - SZ_2M)

/*
 * IAMROOT, 2021.08.14: VA_BITS_MIN: VA 비트가 52인 경우 최소 48까지 사용
 */

#if VA_BITS > 48
#define VA_BITS_MIN		(48)
#else
#define VA_BITS_MIN		(VA_BITS)
#endif

/*
 * IAMROOT, 2021.08.21:
 * 해당 bit의 마지막 주소를 page 크기(마지막 주소)를 계산한다.
 * va == 48인 경우 => -2^(48 - 1) => 0xffff_8000_0000_0000
 *
 * 2^47 = 0x8000_0000_0000
 * -(2^47) = -0x8000_0000_0000 = 0xffff_7fff_ffff_ffff + 1
 *  => 0xffff_8000_0000_0000 => 이 공간의 크기가 256TB
 */
#define _PAGE_END(va)		(-(UL(1) << ((va) - 1)))

/*
 * IAMROOT, 2021.07.10: arch/arm64/kernel/vmlinux.lds.S 파일에서 
		        _text, _end 등이 정의되어 있다.
 */

#define KERNEL_START		_text
#define KERNEL_END		_end
/*
 * IAMROOT, 2021.08.21:
 * - KASAN은 안쓴다고 가정. runtime memory debugger.
 */
/*
 * Generic and tag-based KASAN require 1/8th and 1/16th of the kernel virtual
 * address space for the shadow region respectively. They can bloat the stack
 * significantly, so double the (minimum) stack size when they are in use.
 */
#ifdef CONFIG_KASAN
#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
#define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) \
					+ KASAN_SHADOW_OFFSET)
#define KASAN_THREAD_SHIFT	1
#else
#define KASAN_THREAD_SHIFT	0
#define KASAN_SHADOW_END	(_PAGE_END(VA_BITS_MIN))
#endif /* CONFIG_KASAN */
/*
 * IAMROOT, 2021.09.04:
 * - 최소 16k (CONFIG_KASAN off), 최대 32k (CONFIG_KASAN on)
 */
#define MIN_THREAD_SHIFT	(14 + KASAN_THREAD_SHIFT)
/*
 * IAMROOT, 2021.09.04:
 * - CONFIG_VMAP_STACK : stack이란게 연속된 주소가 필요한데, VMAP_STACK을 사용하면
 *   연속된 가상주소를 이용해서 할당함으로 fragment를 회피하기 위한설정.
 *   64bit 시스템에서는 VA 48bit(PAGE_SIZE = 4kb)인 경우 16kb가 보통이다.
 *
 *   vmap을 사용하면 buddy system을 통해서 order 0를 4개를 가져오며
 *   사용안하는 경우에는 order 2로 연속된 공간을 가져온다.
 */
/*
 * VMAP'd stacks are allocated at page granularity, so we must ensure that such
 * stacks are a multiple of page size.
 */
#if defined(CONFIG_VMAP_STACK) && (MIN_THREAD_SHIFT < PAGE_SHIFT)
#define THREAD_SHIFT		PAGE_SHIFT
#else
#define THREAD_SHIFT		MIN_THREAD_SHIFT
#endif

#if THREAD_SHIFT >= PAGE_SHIFT
#define THREAD_SIZE_ORDER	(THREAD_SHIFT - PAGE_SHIFT)
#endif

#define THREAD_SIZE		(UL(1) << THREAD_SHIFT)

/*
 * By aligning VMAP'd stacks to 2 * THREAD_SIZE, we can detect overflow by
 * checking sp & (1 << THREAD_SHIFT), which we can do cheaply in the entry
 * assembly.
 */
#ifdef CONFIG_VMAP_STACK
#define THREAD_ALIGN		(2 * THREAD_SIZE)
#else
#define THREAD_ALIGN		THREAD_SIZE
#endif

#define IRQ_STACK_SIZE		THREAD_SIZE

#define OVERFLOW_STACK_SIZE	SZ_4K

/*
 * Alignment of kernel segments (e.g. .text, .data).
 *
 *  4 KB granule:  16 level 3 entries, with contiguous bit
 * 16 KB granule:   4 level 3 entries, without contiguous bit
 * 64 KB granule:   1 level 3 entry
 */
#define SEGMENT_ALIGN		SZ_64K

/*
 * Memory types available.
 *
 * IMPORTANT: MT_NORMAL must be index 0 since vm_get_page_prot() may 'or' in
 *	      the MT_NORMAL_TAGGED memory type for PROT_MTE mappings. Note
 *	      that protection_map[] only contains MT_NORMAL attributes.
 */
/*
 * IAMROOT, 2021.08.21:
 * - MT_X는 MAIR_EL1의 index를 나타낸다. MAIR_EL1은 총 64비트로 이루어져있으며,
 *   8비트씩 묶었을 때의 index가 아래의 MT_X이다.
 *
 * - MAIR_EL1의 index와 값의 mapping 정보는 arch/arm64/mm/proc.S 에서
 *   MAIR_EL1_SET을 검색해보면 찾을 수 있다.
 *
 * - page table entry에 memory type을 직접 넣지 않고 indirect 방식으로
 *   하는 이유는 page table entry의 비트수를 절약하기 위해서이다.
 *   page table entry에 memory type을 직접 넣으려면 8비트를 소모해야하는 반면,
 *   MAIR를 이용해 indirect 방식을 활용하면 index를 선택하기 위한 3비트 만으로
 *   해결이 가능하다.
 *
 * - page table entry는 a block or page descriptor라고도 불린다.
 */
#define MT_NORMAL		0
#define MT_NORMAL_TAGGED	1
#define MT_NORMAL_NC		2
#define MT_NORMAL_WT		3
#define MT_DEVICE_nGnRnE	4
#define MT_DEVICE_nGnRE		5
#define MT_DEVICE_GRE		6

/*
 * Memory types for Stage-2 translation
 */
#define MT_S2_NORMAL		0xf
#define MT_S2_DEVICE_nGnRE	0x1

/*
 * Memory types for Stage-2 translation when ID_AA64MMFR2_EL1.FWB is 0001
 * Stage-2 enforces Normal-WB and Device-nGnRE
 */
#define MT_S2_FWB_NORMAL	6
#define MT_S2_FWB_DEVICE_nGnRE	1

#ifdef CONFIG_ARM64_4K_PAGES
#define IOREMAP_MAX_ORDER	(PUD_SHIFT)
#else
#define IOREMAP_MAX_ORDER	(PMD_SHIFT)
#endif

#ifndef __ASSEMBLY__

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/mmdebug.h>
#include <linux/types.h>
#include <asm/bug.h>

extern u64			vabits_actual;
#define PAGE_END		(_PAGE_END(vabits_actual))

extern s64			memstart_addr;
/* PHYS_OFFSET - the physical address of the start of memory. */
#define PHYS_OFFSET		({ VM_BUG_ON(memstart_addr & 1); memstart_addr; })

/* the virtual base of the kernel image */
extern u64			kimage_vaddr;

/* the offset between the kernel virtual and physical mappings */
extern u64			kimage_voffset;

static inline unsigned long kaslr_offset(void)
{
	return kimage_vaddr - KIMAGE_VADDR;
}

/*
 * Allow all memory at the discovery stage. We will clip it later.
 */
#define MIN_MEMBLOCK_ADDR	0
#define MAX_MEMBLOCK_ADDR	U64_MAX

/*
 * PFNs are used to describe any physical page; this means
 * PFN 0 == physical address 0.
 *
 * This is the PFN of the first RAM page in the kernel
 * direct-mapped view.  We assume this is the first page
 * of RAM in the mem_map as well.
 */
#define PHYS_PFN_OFFSET	(PHYS_OFFSET >> PAGE_SHIFT)

/*
 * When dealing with data aborts, watchpoints, or instruction traps we may end
 * up with a tagged userland pointer. Clear the tag to get a sane pointer to
 * pass on to access_ok(), for instance.
 */
#define __untagged_addr(addr)	\
	((__force __typeof__(addr))sign_extend64((__force u64)(addr), 55))

#define untagged_addr(addr)	({					\
	u64 __addr = (__force u64)(addr);					\
	__addr &= __untagged_addr(__addr);				\
	(__force __typeof__(addr))__addr;				\
})

#ifdef CONFIG_KASAN_SW_TAGS
#define __tag_shifted(tag)	((u64)(tag) << 56)
#define __tag_reset(addr)	__untagged_addr(addr)
#define __tag_get(addr)		(__u8)((u64)(addr) >> 56)
#else
#define __tag_shifted(tag)	0UL
#define __tag_reset(addr)	(addr)
#define __tag_get(addr)		0
#endif /* CONFIG_KASAN_SW_TAGS */

static inline const void *__tag_set(const void *addr, u8 tag)
{
	u64 __addr = (u64)addr & ~__tag_shifted(0xff);
	return (const void *)(__addr | __tag_shifted(tag));
}

/*
 * Physical vs virtual RAM address space conversion.  These are
 * private definitions which should NOT be used outside memory.h
 * files.  Use virt_to_phys/phys_to_virt/__pa/__va instead.
 */


/*
 * The linear kernel range starts at the bottom of the virtual address
 * space. Testing the top bit for the start of the region is a
 * sufficient check and avoids having to worry about the tag.
 */
/*
 * IAMROOT, 2021.10.02:
 * - __virt_to_phys_nodebug(x)
 *   x가 리니어매핑된 주소라면 리니어매핑 물리주소 변환을, 아니면
 *   kimg_to_phys 변환을 수행한다.
 *
 * - __is_lm_address
 *   리니어매핑 가상주소인 경우 true
 *   범위 0xffff_0000_0000_0000 ~ 0xffff_7fff_ffff_ffff
 *
 * - __lm_to_phys
 *   리니어매핑 가상주소를 물리주소로 변환한다.
 *   PAGE_OFFSET bits를 전부 clear시키고 PHYS_OFFSET을 더하는것으로
 *   물리주소가 구해진다.
 *
 * - __kimg_to_phys, __pa_symbol_nodebug
 *   image 가상주소를 물리주소로 변환한다. randomize offset을 빼는것만으로
 *   구해진다.
 */
#define __is_lm_address(addr)	(!(((u64)addr) & BIT(vabits_actual - 1)))

#define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
#define __kimg_to_phys(addr)	((addr) - kimage_voffset)
#define __virt_to_phys_nodebug(x) ({					\
	phys_addr_t __x = (phys_addr_t)(__tag_reset(x));		\
	__is_lm_address(__x) ? __lm_to_phys(__x) : __kimg_to_phys(__x);	\
})

#define __pa_symbol_nodebug(x)	__kimg_to_phys((phys_addr_t)(x))

#ifdef CONFIG_DEBUG_VIRTUAL
extern phys_addr_t __virt_to_phys(unsigned long x);
extern phys_addr_t __phys_addr_symbol(unsigned long x);
#else
#define __virt_to_phys(x)	__virt_to_phys_nodebug(x)
#define __phys_addr_symbol(x)	__pa_symbol_nodebug(x)
#endif /* CONFIG_DEBUG_VIRTUAL */
/*
 * IAMROOT, 2021.10.02:
 * - __phys_to_virt
 *   물리주소를 리니어매핑된 가상주소로 변환.
 * - __phys_to_kimg
 *   물리주소를 image로 매핑된 가상주소도 변환.
 */
#define __phys_to_virt(x)	((unsigned long)((x) - PHYS_OFFSET) | PAGE_OFFSET)
#define __phys_to_kimg(x)	((unsigned long)((x) + kimage_voffset))

/*
 * Convert a page to/from a physical address
 */
#define page_to_phys(page)	(__pfn_to_phys(page_to_pfn(page)))
#define phys_to_page(phys)	(pfn_to_page(__phys_to_pfn(phys)))

/*
 * Note: Drivers should NOT use these.  They are the wrong
 * translation for translating DMA addresses.  Use the driver
 * DMA support - see dma-mapping.h.
 */
#define virt_to_phys virt_to_phys
static inline phys_addr_t virt_to_phys(const volatile void *x)
{
	return __virt_to_phys((unsigned long)(x));
}

#define phys_to_virt phys_to_virt
static inline void *phys_to_virt(phys_addr_t x)
{
	return (void *)(__phys_to_virt(x));
}

/*
 * Drivers should NOT use these either.
 */
/*
 * IAMROOT, 2021.10.02:
 * kernel은 리니어 매핑이 되있기 때문에 PHYS_OFFSET을 +- 하고 PAGE_OFFSET
 * 을 OR 해주는것만으로도 va <-> pa 변환이 가능하다.
 *
 * - __pa
 *   va를 pa로 변환. kernel memory 전용.
 *
 * - __va
 *   pa를 va로 변환. kernel memory 전용.
 */
#define __pa(x)			__virt_to_phys((unsigned long)(x))
#define __pa_symbol(x)		__phys_addr_symbol(RELOC_HIDE((unsigned long)(x), 0))
#define __pa_nodebug(x)		__virt_to_phys_nodebug((unsigned long)(x))
#define __va(x)			((void *)__phys_to_virt((phys_addr_t)(x)))
#define pfn_to_kaddr(pfn)	__va((pfn) << PAGE_SHIFT)
#define virt_to_pfn(x)		__phys_to_pfn(__virt_to_phys((unsigned long)(x)))
#define sym_to_pfn(x)		__phys_to_pfn(__pa_symbol(x))

/*
 *  virt_to_page(x)	convert a _valid_ virtual address to struct page *
 *  virt_addr_valid(x)	indicates whether a virtual address is valid
 */
#define ARCH_PFN_OFFSET		((unsigned long)PHYS_PFN_OFFSET)

#if !defined(CONFIG_SPARSEMEM_VMEMMAP) || defined(CONFIG_DEBUG_VIRTUAL)
#define virt_to_page(x)		pfn_to_page(virt_to_pfn(x))
#else
#define page_to_virt(x)	({						\
	__typeof__(x) __page = x;					\
	u64 __idx = ((u64)__page - VMEMMAP_START) / sizeof(struct page);\
	u64 __addr = PAGE_OFFSET + (__idx * PAGE_SIZE);			\
	(void *)__tag_set((const void *)__addr, page_kasan_tag(__page));\
})

#define virt_to_page(x)	({						\
	u64 __idx = (__tag_reset((u64)x) - PAGE_OFFSET) / PAGE_SIZE;	\
	u64 __addr = VMEMMAP_START + (__idx * sizeof(struct page));	\
	(struct page *)__addr;						\
})
#endif /* !CONFIG_SPARSEMEM_VMEMMAP || CONFIG_DEBUG_VIRTUAL */

#define virt_addr_valid(addr)	({					\
	__typeof__(addr) __addr = addr;					\
	__is_lm_address(__addr) && pfn_valid(virt_to_pfn(__addr));	\
})

void dump_mem_limit(void);
#endif /* !ASSEMBLY */

/*
 * Given that the GIC architecture permits ITS implementations that can only be
 * configured with a LPI table address once, GICv3 systems with many CPUs may
 * end up reserving a lot of different regions after a kexec for their LPI
 * tables (one per CPU), as we are forced to reuse the same memory after kexec
 * (and thus reserve it persistently with EFI beforehand)
 */
#if defined(CONFIG_EFI) && defined(CONFIG_ARM_GIC_V3_ITS)
# define INIT_MEMBLOCK_RESERVED_REGIONS	(INIT_MEMBLOCK_REGIONS + NR_CPUS + 1)
#endif

#include <asm-generic/memory_model.h>

#endif /* __ASM_MEMORY_H */
