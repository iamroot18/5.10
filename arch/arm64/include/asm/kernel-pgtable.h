/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel page table mapping
 *
 * Copyright (C) 2015 ARM Ltd.
 */

#ifndef __ASM_KERNEL_PGTABLE_H
#define __ASM_KERNEL_PGTABLE_H

#include <asm/pgtable-hwdef.h>
#include <asm/sparsemem.h>

/*
 * The linear mapping and the start of memory are both 2M aligned (per
 * the arm64 booting.txt requirements). Hence we can use section mapping
 * with 4K (section size = 2M) but not with 16K (section size = 32M) or
 * 64K (section size = 512M).
 */
#ifdef CONFIG_ARM64_4K_PAGES
#define ARM64_SWAPPER_USES_SECTION_MAPS 1
#else
#define ARM64_SWAPPER_USES_SECTION_MAPS 0
#endif

/*
 * The idmap and swapper page tables need some space reserved in the kernel
 * image. Both require pgd, pud (4 levels only) and pmd tables to (section)
 * map the kernel. With the 64K page configuration, swapper and idmap need to
 * map to pte level. The swapper also maps the FDT (see __create_page_tables
 * for more information). Note that the number of ID map translation levels
 * could be increased on the fly if system RAM is out of reach for the default
 * VA range, so pages required to map highest possible PA are reserved in all
 * cases.
 */
/*
 * IAMROOT, 2021.08.14: 
 * - SWAPPER_PGTABLE_LEVELS: 정규 커널 페이지 테이블이 사용할 레벨 수
 *                           default arm64 커널은 CONFIG_PGTABLE_LEVELS=4
 *                           4K 페이지 테이블을 사용하는 경우 섹션 매핑을 
 *                           사용할 수 있으므로 1 단계 내릴 수 있다.
 *                           (4K, 섹션 매핑 사용하므로 디폴트=3)
 * - IDMAP_PGTABLE_LEVLES:   va=pa 1:1 id 매핑용 페이지 테이블이 사용할 단계 수
 *                           (4K, 섹션 매핑 사용하므로 디폴트=3)
 * 
 * - 위의 두 테이블 레벨 산출의 기준은 
 *    SWAPPER -> VA 기준으로
 *    IDMAP   -> PA 기준으로 
 */
#if ARM64_SWAPPER_USES_SECTION_MAPS
#define SWAPPER_PGTABLE_LEVELS	(CONFIG_PGTABLE_LEVELS - 1)
#define IDMAP_PGTABLE_LEVELS	(ARM64_HW_PGTABLE_LEVELS(PHYS_MASK_SHIFT) - 1)
#else
#define SWAPPER_PGTABLE_LEVELS	(CONFIG_PGTABLE_LEVELS)
#define IDMAP_PGTABLE_LEVELS	(ARM64_HW_PGTABLE_LEVELS(PHYS_MASK_SHIFT))
#endif


/*
 * If KASLR is enabled, then an offset K is added to the kernel address
 * space. The bottom 21 bits of this offset are zero to guarantee 2MB
 * alignment for PA and VA.
 *
 * For each pagetable level of the swapper, we know that the shift will
 * be larger than 21 (for the 4KB granule case we use section maps thus
 * the smallest shift is actually 30) thus there is the possibility that
 * KASLR can increase the number of pagetable entries by 1, so we make
 * room for this extra entry.
 *
 * Note KASLR cannot increase the number of required entries for a level
 * by more than one because it increments both the virtual start and end
 * addresses equally (the extra entry comes from the case where the end
 * address is just pushed over a boundary and the start address isn't).
 */

#ifdef CONFIG_RANDOMIZE_BASE
#define EARLY_KASLR	(1)
#else
#define EARLY_KASLR	(0)
#endif

/*
 * IAMROOT, 2021.08.14: 
 * - EARLY_ENTRIES: vstart ~ vend 범위를 early 매핑하기 위해 shift 단위로 
 *  필요한 엔트리 수 (0인 경우 최소 1, EARLY_KASLR이 있는 경우 1 추가)
 *
 * - 4K 기준일때 약 30M 커널 이미지 가정 시 EARLY 매핑에 필요한 엔트리 수
 * - 실제 PGD용:  1개
 * - EARLY_PGDS:  1개
 * - EARLY_PUDS:  0개
 * - EARLY_PMDS:  1개 (1G 정렬에 걸친 이미지는 2)
 * - EARLY_PAGES: 1+1+0+1=3개(or 4개)
 */
#define EARLY_ENTRIES(vstart, vend, shift) (((vend) >> (shift)) \
					- ((vstart) >> (shift)) + 1 + EARLY_KASLR)

#define EARLY_PGDS(vstart, vend) (EARLY_ENTRIES(vstart, vend, PGDIR_SHIFT))

/*
 * IAMROOT, 2021.08.14: 
 * - 4K, 섹션 매핑을 허용하므로 SWAPER_PGTABLE_LEVES=3 (디폴트)
 */
#if SWAPPER_PGTABLE_LEVELS > 3
#define EARLY_PUDS(vstart, vend) (EARLY_ENTRIES(vstart, vend, PUD_SHIFT))
#else
#define EARLY_PUDS(vstart, vend) (0)
#endif

#if SWAPPER_PGTABLE_LEVELS > 2
#define EARLY_PMDS(vstart, vend) (EARLY_ENTRIES(vstart, vend, SWAPPER_TABLE_SHIFT))
#else
#define EARLY_PMDS(vstart, vend) (0)
#endif

#define EARLY_PAGES(vstart, vend) ( 1 			/* PGDIR page */				\
			+ EARLY_PGDS((vstart), (vend)) 	/* each PGDIR needs a next level page table */	\
			+ EARLY_PUDS((vstart), (vend))	/* each PUD needs a next level page table */	\
			+ EARLY_PMDS((vstart), (vend)))	/* each PMD needs a next level page table */
/*
 * IAMROOT, 2021.08.14: 
 * - 초기 커널 페이지 테이블 init_pg_dir과 idmap_pg_dir용 사이즈를 산출한다.
 *   early 페이지로 계산한다.
 *
 * - 4K, 약 30M 단위인 경우
 * - INIT_DIR_SIZE:  3 * 4K = 12K (커널의 가상주소 범위가 1G 이내 정렬된 경우)
 * - IDMAP_DIR_SIZE: 3 * 4K = 12K (커널의 물리주소 범위가 1G 이내 정렬된 경우)
 */
#define INIT_DIR_SIZE (PAGE_SIZE * EARLY_PAGES(KIMAGE_VADDR, _end))
#define IDMAP_DIR_SIZE		(IDMAP_PGTABLE_LEVELS * PAGE_SIZE)

#ifdef CONFIG_ARM64_SW_TTBR0_PAN
#define RESERVED_TTBR0_SIZE	(PAGE_SIZE)
#else
#define RESERVED_TTBR0_SIZE	(0)
#endif

/* Initial memory map size */
#if ARM64_SWAPPER_USES_SECTION_MAPS
#define SWAPPER_BLOCK_SHIFT	SECTION_SHIFT
#define SWAPPER_BLOCK_SIZE	SECTION_SIZE
#define SWAPPER_TABLE_SHIFT	PUD_SHIFT
#else
#define SWAPPER_BLOCK_SHIFT	PAGE_SHIFT
#define SWAPPER_BLOCK_SIZE	PAGE_SIZE
#define SWAPPER_TABLE_SHIFT	PMD_SHIFT
#endif

/* The size of the initial kernel direct mapping */
#define SWAPPER_INIT_MAP_SIZE	(_AC(1, UL) << SWAPPER_TABLE_SHIFT)

/*
 * Initial memory map attributes.
 */
/*
 * IAMROOT, 2021.08.21:
 *
 * - SWAPPER_PMD_FLAGS
 *   - PMD_TYPE_SECT: 현재 table entry는 section임을 나타냄.
 *   - PMD_SECT_AF: Access Flag (Region accessed)
 *   - PMD_SECT_S: Inner Share
 */
#define SWAPPER_PTE_FLAGS	(PTE_TYPE_PAGE | PTE_AF | PTE_SHARED)
#define SWAPPER_PMD_FLAGS	(PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S)

/*
 * IAMROOT, 2021.08.21:
 *
 * - SWAPPER_MM_MMUFLAGS
 *   - PMD_ATTRINDX, PTE_ATTRINDX:
 *       page table entry(== A block or page descriptor)의 필드 중
 *       Lower Attributes에 속하는 indx[4:2]에 MAIR_EL1의 index를 설정한다.
 *       indx[4:2]는 memory type을 결정하기 위해 사용된다. 자세한 내용은
 *       arch/arm64/include/asm/memory.h 에 있는 MT_NORMAL참조.
 */
#if ARM64_SWAPPER_USES_SECTION_MAPS
#define SWAPPER_MM_MMUFLAGS	(PMD_ATTRINDX(MT_NORMAL) | SWAPPER_PMD_FLAGS)
#else
#define SWAPPER_MM_MMUFLAGS	(PTE_ATTRINDX(MT_NORMAL) | SWAPPER_PTE_FLAGS)
#endif

/*
 * To make optimal use of block mappings when laying out the linear
 * mapping, round down the base of physical memory to a size that can
 * be mapped efficiently, i.e., either PUD_SIZE (4k granule) or PMD_SIZE
 * (64k granule), or a multiple that can be mapped using contiguous bits
 * in the page tables: 32 * PMD_SIZE (16k granule)
 */
#if defined(CONFIG_ARM64_4K_PAGES)
#define ARM64_MEMSTART_SHIFT		PUD_SHIFT
#elif defined(CONFIG_ARM64_16K_PAGES)
#define ARM64_MEMSTART_SHIFT		(PMD_SHIFT + 5)
#else
#define ARM64_MEMSTART_SHIFT		PMD_SHIFT
#endif

/*
 * sparsemem vmemmap imposes an additional requirement on the alignment of
 * memstart_addr, due to the fact that the base of the vmemmap region
 * has a direct correspondence, and needs to appear sufficiently aligned
 * in the virtual address space.
 */
#if defined(CONFIG_SPARSEMEM_VMEMMAP) && ARM64_MEMSTART_SHIFT < SECTION_SIZE_BITS
#define ARM64_MEMSTART_ALIGN	(1UL << SECTION_SIZE_BITS)
#else
#define ARM64_MEMSTART_ALIGN	(1UL << ARM64_MEMSTART_SHIFT)
#endif

#endif	/* __ASM_KERNEL_PGTABLE_H */
