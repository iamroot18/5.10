/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 * Copyright (C) 2013 Mark Salter <msalter@redhat.com>
 *
 * Adapted from arch/x86 version.
 *
 */

#ifndef _ASM_ARM64_FIXMAP_H
#define _ASM_ARM64_FIXMAP_H

#ifndef __ASSEMBLY__
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <asm/boot.h>
#include <asm/page.h>
#include <asm/pgtable-prot.h>
/*
 * IAMROOT, 2021.09.04:
 * - 가상주소의 특정범위를 특정용도로 고정하여 사용하기 위한 정의이다.
 *   전체 size는 약 6MB가 조금 못되게 나온다.
 *
 * - fixed map
 *   처음 compile time에 고정된 가상주소. 모든 메모리는 dynimic memory
 *   mappting에 의해 관리가 되야 되는데 처음엔 아직 동작을 안하고 있으므로
 *   임시로 사용하기 위함. 또한 몇가지 기능을 위한 고정 주소 또한 제공한다.
 *
 * - FIX_EARLYCON_MEM_BASE 같은 기능은 미리 driver를 부팅하기전에
 *   무슨 driver가 있는지에 대한 정보등을 제공하기 위한 용도이다.
 *
 * - FIX_TEXT_POKE0 : kernel code가 read only mapping이 되있는데,
 *   이 주소는 read write 영역이고, kernel code를 수정할때 사용한다.
 *
 * - FIX_ENTRY_TRAMP_DATA : 보안을 위해 유저측에서 kernel측을 감추기 위해
 *   사용한다.
 *
 * - FIX_PGD... : FIX_TEXT_POKE0과 비슷한 이유로 인해 page table 수정할때
 *   잠시 mapping하기 위한 것이며, 4개의 page table을 전부 mapping후
 *   atomic하게 수정한다.
 *
 * ----------
 *
 * - fixed_address는 __end_of_permanent_fixed_addresses를 기준으로
 *   2개로 나눠진다.
 *   여기서 FIXMAP_SIZE는 __end_of_fixed_addresses아래쪽의 FIX_PGD..등은
 *   제외한 크기가 된다.
 *
 */
/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process.
 *
 * Each enum increment in these 'compile-time allocated'
 * memory buffers is page-sized. Use set_fixmap(idx,phys)
 * to associate physical memory with a fixmap index.
 */
enum fixed_addresses {
	FIX_HOLE,

	/*
	 * Reserve a virtual window for the FDT that is 2 MB larger than the
	 * maximum supported size, and put it at the top of the fixmap region.
	 * The additional space ensures that any FDT that does not exceed
	 * MAX_FDT_SIZE can be mapped regardless of whether it crosses any
	 * 2 MB alignment boundaries.
	 *
	 * Keep this at the top so it remains 2 MB aligned.
	 */
#define FIX_FDT_SIZE		(MAX_FDT_SIZE + SZ_2M)
	FIX_FDT_END,
	FIX_FDT = FIX_FDT_END + FIX_FDT_SIZE / PAGE_SIZE - 1,

	FIX_EARLYCON_MEM_BASE,
	FIX_TEXT_POKE0,

#ifdef CONFIG_ACPI_APEI_GHES
	/* Used for GHES mapping from assorted contexts */
	FIX_APEI_GHES_IRQ,
	FIX_APEI_GHES_SEA,
#ifdef CONFIG_ARM_SDE_INTERFACE
	FIX_APEI_GHES_SDEI_NORMAL,
	FIX_APEI_GHES_SDEI_CRITICAL,
#endif
#endif /* CONFIG_ACPI_APEI_GHES */

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	FIX_ENTRY_TRAMP_DATA,
	FIX_ENTRY_TRAMP_TEXT,
#define TRAMP_VALIAS		(__fix_to_virt(FIX_ENTRY_TRAMP_TEXT))
#endif /* CONFIG_UNMAP_KERNEL_AT_EL0 */
/*
 * IAMROOT, 2021.09.04:
 * - 약 4MB(PAGE_SIZE 4kb 기준).
 *  크기를 적당히 계산해보면
 *  FIX_FDT_SIZE = 4MB가 되고 FIX_EARLYCON_MEM_BASE, FIX_TEXT_POKE0,
 *  FIX_ENTRY_TRAMP_DATA, FIX_ENTRY_TRAMP_TEXT가 존재 한다고할때
 *  4MB + 16KB 크기가 된다.
 *
 */
	__end_of_permanent_fixed_addresses,

	/*
	 * Temporary boot-time mappings, used by early_ioremap(),
	 * before ioremap() is functional.
	 */
#define NR_FIX_BTMAPS		(SZ_256K / PAGE_SIZE)
#define FIX_BTMAPS_SLOTS	7
#define TOTAL_FIX_BTMAPS	(NR_FIX_BTMAPS * FIX_BTMAPS_SLOTS)

/*
 * IAMROOT, 2021.09.04:
 * - FIX_BTMAP_END ~ __end_of_fixed_addresses :
 *   early_ioremap 영역. 256kb * 7
 *   7개 장비를 부팅하자마자 쓸수 있게 하는 영역.
 */
	FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
	FIX_BTMAP_BEGIN = FIX_BTMAP_END + TOTAL_FIX_BTMAPS - 1,

	/*
	 * Used for kernel page table creation, so unmapped memory may be used
	 * for tables.
	 */
	FIX_PTE,
	FIX_PMD,
	FIX_PUD,
	FIX_PGD,

	__end_of_fixed_addresses
};

#define FIXADDR_SIZE	(__end_of_permanent_fixed_addresses << PAGE_SHIFT)
/*
 * IAMROOT, 2021.09.07:
 * arch/arm64/include/asm/memory.h 에서 그려논 memory map 참고하면 어느
 * 위치 쯤에 있는지 파악이된다.
 */
#define FIXADDR_START	(FIXADDR_TOP - FIXADDR_SIZE)

#define FIXMAP_PAGE_IO     __pgprot(PROT_DEVICE_nGnRE)

void __init early_fixmap_init(void);

#define __early_set_fixmap __set_fixmap

#define __late_set_fixmap __set_fixmap
#define __late_clear_fixmap(idx) __set_fixmap((idx), 0, FIXMAP_PAGE_CLEAR)

extern void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot);

#include <asm-generic/fixmap.h>

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_ARM64_FIXMAP_H */
