/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Low-level CPU initialisation
 * Based on arch/arm/kernel/head.S
 *
 * Copyright (C) 1994-2002 Russell King
 * Copyright (C) 2003-2012 ARM Ltd.
 * Authors:	Catalin Marinas <catalin.marinas@arm.com>
 *		Will Deacon <will.deacon@arm.com>
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/pgtable.h>

#include <asm/asm_pointer_auth.h>
#include <asm/assembler.h>
#include <asm/boot.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/cache.h>
#include <asm/cputype.h>
#include <asm/elf.h>
#include <asm/image.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_arm.h>
#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>
#include <asm/page.h>
#include <asm/scs.h>
#include <asm/smp.h>
#include <asm/sysreg.h>
#include <asm/thread_info.h>
#include <asm/virt.h>

#include "efi-header.S"

/*
 * IAMROOT, 2021.07.10:
 * - 해당 코드는 bootloader에 의한 최소한의 초기화 작업이후의 코드임을 알린다.
 * - KERNEL_START --> 커널 시작 가상 주소(_text)
 * - 컴파일 타임에(페이지 프레임 크기와 페이지 테이블 사용 단계) 결정
 *   -> 0xFFFF_****_****_****
 *   -> KASLR 옵션을 사용하는 경우 실제 커널 가상 주소는 런타임에 변경된다.
 */
#define __PHYS_OFFSET	KERNEL_START

#if (PAGE_OFFSET & 0x1fffff) != 0
#error PAGE_OFFSET must be at least 2MB aligned
#endif

/*
 * IAMROOT, 2021.07.10:
 * - DTB(Device Tree Blob)
 *   디바이스 트리가 컴파일되어 빅엔디언 형태의 바이너리이다.
 *   FDT(Flattened Device Tree)라고도 불리운다.
 *   커널이 동작하기 위한 디바이스의 물리주소가 기록되어 있음.
 *   서버나 pc는 ACPI table이 있기때문에 필요가 없음
 *   SoC 기반의(ARM, embeded) 제품들은 UEFI가 없기때문에 device tree가 필요함.
 *   최근에 UEFI BIOS를 가진 ARM server는 ACPI 와 DT를 둘다 사용가능하다.
 *
 * 아래 요구사항이 필요한 이유:
 * 1. mmu를 키려고 하기때문에 켜있으면 안됌.
 * 2. 기존에 mmu 없이 boot loader가 동작했기 때문에 꺼져 있는게 정상.
 *    (ARM 계열은 MMU가 꺼져 있으면 데이터 캐시를 킬수 없다.
 *    일부 SoC에서 MMU off 상태에서 명령 캐시는 on 가능하다고 함)
 * - mmu = off 이유
 *   Startup entry point에서 mmu가 on 이라면 CPU가 명령어를 수행할 때
 *   메모리 주소값을 가상 주소로 해석하여 MMU가 물리 주소로 변환함.
 *   매핑 테이블이 존재하지 않기 때문에 의도치 않은 작업들이 수행됨.
 * - d-cache = off 이유
 *   Startup 코드에서는 물리 주소에서 데이터를 직접 읽거나 써야하는데
 *   d-cache가 on 되어 있다면 캐시 메모리로 접근을 시도하게 되어
 *   의도치 않은 작업들이 수행됨.
 * reference
 * - https://www.programmersought.com/article/20796227528/
 *
 * bootloader가 DRAM의 위치와 관계없이 relocatable한 code로 만들어주는 부분.
 * 아래 문맥의 callee : kernel caller: bootloader
 */

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * The requirements are:
 *   MMU = off, D-cache = off, I-cache = on or off,
 *   x0 = physical address to the FDT blob.
 *
 * This code is mostly position independent so you call this at
 * __pa(PAGE_OFFSET).
 *
 * Note that the callee-saved registers are used for storing variables
 * that are useful before the MMU is enabled. The allocations are described
 * in the entry routines.
 */
	__HEAD
_head:
	/*
	 * DO NOT MODIFY. Image header expected by Linux boot-loaders.
	 */
#ifdef CONFIG_EFI
	/*
	 * This add instruction has no meaningful effect except that
	 * its opcode forms the magic "MZ" signature required by UEFI.
	 */

/*
 * IAMROOT, 2021.07.10:
 * - add 는 커널입장에서는 의미없이 동작하는 코드지만,
 *   외부에서 이커널을 볼때, UEFI를 지원한다는 것을 의미하는
 *   MZ라는 MAGIC NUMBER를 확인 할 수 있다.
 */
	add	x13, x18, #0x16
	b	primary_entry
#else
/* IAMROOT, 2021.07.10: CONFIG_EFI=n로 동작하기 위해선 DT를 수동으로 작성 해줘야한다.*/
	b	primary_entry			// branch to kernel start, magic
	.long	0				// reserved
#endif
	.quad	0				// Image load offset from start of RAM, little-endian
	le64sym	_kernel_size_le			// Effective size of kernel image, little-endian
	le64sym	_kernel_flags_le		// Informative flags, little-endian
	.quad	0				// reserved
	.quad	0				// reserved
	.quad	0				// reserved
	.ascii	ARM64_IMAGE_MAGIC		// Magic number
#ifdef CONFIG_EFI
	.long	pe_header - _head		// Offset to the PE header.

pe_header:
	__EFI_PE_HEADER
#else
	.long	0				// reserved
#endif

	__INIT

	/*
	 * The following callee saved general purpose registers are used on the
	 * primary lowlevel boot path:
	 *
	 *  Register   Scope                      Purpose
	 *  x21        primary_entry() .. start_kernel()        FDT pointer passed at boot in x0
	 *  x23        primary_entry() .. start_kernel()        physical misalignment/KASLR offset
	 *  x28        __create_page_tables()                   callee preserved temp register
	 *  x19/x20    __primary_switch()                       callee preserved temp registers
	 *  x24        __primary_switch() .. relocate_kernel()  current RELR displacement
	 */
/*
 * IAMROOT, 2021.07.17:
 *
 * - SYM_CODE_START() 해석:
 *      .globl primary_entry;
 *      .align 2;
 *      primary_entry:
 *
 * - .globl 의미
 *   해당 label을 외부에서 볼 수 있도록 하는 지시자.
 *   소스 코드가 여러개로 분리되어 있다면 linker에서 해당 symbol을
 *   찾을 수 있도록 사용하는 지시자.
 */
SYM_CODE_START(primary_entry)
	bl	preserve_boot_args
	bl	el2_setup			// Drop to EL1, w0=cpu_boot_mode
/*
 * IAMROOT, 2021.08.14: 
 * - nVHE로 동작하는 경우 아래 코드는 EL2->EL1으로 변경된 채 동작한다.
 *
 * - 커널 물리주소 위치를 읽어온 후 2M 정렬단위의 하위 offset를 
 *   x23에 기록한다.
 *
 * ----
 *   TCR : Table Control Register
 */
	adrp	x23, __PHYS_OFFSET
	and	x23, x23, MIN_KIMG_ALIGN - 1	// KASLR offset, defaults to 0
	bl	set_cpu_boot_mode_flag
	bl	__create_page_tables
	/*
	 * The following calls CPU setup code, see arch/arm64/mm/proc.S for
	 * details.
	 * On return, the CPU will be ready for the MMU to be turned on and
	 * the TCR will have been set.
	 */
	bl	__cpu_setup			// initialise processor
	b	__primary_switch
SYM_CODE_END(primary_entry)

/*
 * Preserve the arguments passed by the bootloader in x0 .. x3
 */

/*
 * IAMROOT, 2021.07.17:
 *
 * - SYM_CODE_START_LOCAL() 해석
 *      .align 2;
 *      preserve_boot_args:
 */
SYM_CODE_START_LOCAL(preserve_boot_args)
	mov	x21, x0				// x21=FDT

/* IAMROOT, 2021.07.17: x0 = &boot_args[0] */
	adr_l	x0, boot_args			// record the contents of

/*
 * IAMROOT, 2021.07.17:
 *
 * str x21, boot_args
 * str x1, boot_args + 8 = boot_args[1];
 */
	stp	x21, x1, [x0]			// x0 .. x3 at kernel entry

/*
 * IAMROOT, 2021.07.17:
 *
 * str x2, boot_args[2];
 * str x3, boot_args[3];
 */
	stp	x2, x3, [x0, #16]

/*
 * IAMROOT, 2021.07.17:
 *
 * dmb: Data Memory Barrier
 * sy : Any - Any : ALL (시스템에 있는 모든 코어)
 *
 * - Modern SMP arch에서 발생할 수 있는 문제
 *   stp와 __inval_dcache_area 중 어느 것이 더 먼저 수행될 지 보장하지 못함.
 *   __inval_dcahce_area가 먼저 수행되는것을 방지하고 stp 명령어의 수행 결과를
 *   보장하기 위해 memory barrier 명령어를 이용한다.
 * - 캐시와의 관계성은?
 *   x0 .. x3까지의 모든 데이터를 boot_args에 저장하고 난 뒤 확실하게
 *   정리하고, 그 이후에 데이터 캐시를 클린하도록 중간에 베리어 명령을 수행한다.
 */
	dmb	sy				// needed before dc ivac with

/*
 * IAMROOT, 2021.07.17:
 * 0x20: boot_args 배열의 전체 크기, sizeof(boot_args)
 * x0: &boot_args
 * x1: __inval_dcache_area의 size args로 넘어감.
 */
	mov	x1, #0x20			// 4 x 8 bytes
	b	__inval_dcache_area		// tail call
SYM_CODE_END(preserve_boot_args)

/*
 * IAMROOT, 2021.08.28:
 * - pgd entry중에 하나를 그다음 테이블에 연결하기 위함.
 *   page table을 하나 추가하는 개념이 되고,
 *   현재 tbl은 PGD이고 이 다음 PUD를 잇기 위함이며 
 *   다음 page table은 tbl + PAGE_SIZE address이므로,
 *   그 주소를 가져와 해당 pud address에 해당하는 index에 값을 저장한다.
 */
/*
 * Macro to create a table entry to the next page.
 *
 *	tbl:	page table address
 *	virt:	virtual address
 *	shift:	#imm page table shift
 *	ptrs:	#imm pointers per table page
 *
 * Preserves:	virt
 * Corrupts:	ptrs, tmp1, tmp2
 * Returns:	tbl -> next level table page address
 */
	.macro	create_table_entry, tbl, virt, shift, ptrs, tmp1, tmp2
	add	\tmp1, \tbl, #PAGE_SIZE
	phys_to_pte \tmp2, \tmp1
	orr	\tmp2, \tmp2, #PMD_TYPE_TABLE	// address of next table and entry type
	lsr	\tmp1, \virt, #\shift
	sub	\ptrs, \ptrs, #1
	and	\tmp1, \tmp1, \ptrs		// table index
	str	\tmp2, [\tbl, \tmp1, lsl #3]
	add	\tbl, \tbl, #PAGE_SIZE		// next level table page
	.endm
/*
 * IAMROOT, 2021.08.21:
 * - compute_indices에서 구해온 index를 가지고,
 * 해당 table entry에 해당하는 물리주소(rtbl)의 속성을 더하고 각 table entry에 mapping하는
 * 역할을 수행한다.
 *
 * b.ls : unsgiend less or same
 * @의 의미 : macro에서 branch가 필요할경우 일반 분기문처럼 tag를 지정해줘야되는데 macro에서는
 * 그렇게 하질 못하므로 compile가 자동으로 tag의 번호를 생성해주게 한다.
 */
/*
 * Macro to populate page table entries, these entries can be pointers to the next level
 * or last level entries pointing to physical memory.
 *
 *	tbl:	page table address
 *	rtbl:	pointer to page table or physical memory
 *	index:	start index to write
 *	eindex:	end index to write - [index, eindex] written to
 *	flags:	flags for pagetable entry to or in
 *	inc:	increment to rtbl between each entry
 *	tmp1:	temporary variable
 *
 * Preserves:	tbl, eindex, flags, inc
 * Corrupts:	index, tmp1
 * Returns:	rtbl
 */
	.macro populate_entries, tbl, rtbl, index, eindex, flags, inc, tmp1
.Lpe\@:	phys_to_pte \tmp1, \rtbl
	orr	\tmp1, \tmp1, \flags	// tmp1 = table entry
	str	\tmp1, [\tbl, \index, lsl #3]
	add	\rtbl, \rtbl, \inc	// rtbl = pa next level
	add	\index, \index, #1
	cmp	\index, \eindex
	b.ls	.Lpe\@
	.endm

/*
 * IAMROOT, 2021.08.21:
 * - macro에 들어온 table의 vstart, vend의 범위와 shift, ptrs를 가지고
 *   istart, iend의 index값과 해당 table의 count를 계산한다.
 *   count는 실제 entry의 개수보다 1이 작은 값이 된다.
 *
 *   ---
 *   ptrs
 *   
 *   - PGD table : entry 값 (count + 1) 이 1이 나옴.
 *       istart = (vstart >> 39) & (0x1ff)
 *       iend = (vend >> 39) & (0x1ff)
 *       count = iend - istart = 0
 *       table 크기가 작기때문에 보통 entry 값이 한개가 나옴.
 *
 *   - PUD table : shift 39값을 30으로 치환해서 계산. 역시 1개의 entry만 나옴
 *   - PMD table : shift를 21값으로 치환해서 계산. 2MB 범위 이므로 여러개가 나올수있음.
 *
 *   그래서 해당 table의 istart, iend, count의 계산 결과 값이 나온다.
 */
/*
 * Compute indices of table entries from virtual address range. If multiple entries
 * were needed in the previous page table level then the next page table level is assumed
 * to be composed of multiple pages. (This effectively scales the end index).
 *
 *	vstart:	virtual address of start of range
 *	vend:	virtual address of end of range
 *	shift:	shift used to transform virtual address into index
 *	ptrs:	number of entries in page table
 *	istart:	index in table corresponding to vstart
 *	iend:	index in table corresponding to vend
 *	count:	On entry: how many extra entries were required in previous level, scales
 *			  our end index.
 *		On exit: returns how many extra entries required for next page table level
 *
 * Preserves:	vstart, vend, shift, ptrs
 * Returns:	istart, iend, count
 */
	.macro compute_indices, vstart, vend, shift, ptrs, istart, iend, count
	lsr	\iend, \vend, \shift
	mov	\istart, \ptrs
	sub	\istart, \istart, #1
	and	\iend, \iend, \istart	// iend = (vend >> shift) & (ptrs - 1)
	mov	\istart, \ptrs
	mul	\istart, \istart, \count
	add	\iend, \iend, \istart	// iend += (count - 1) * ptrs
					// our entries span multiple tables

	lsr	\istart, \vstart, \shift
	mov	\count, \ptrs
	sub	\count, \count, #1
	and	\istart, \istart, \count

	sub	\count, \iend, \istart
	.endm
/*
 * IAMROOT, 2021.08.21:
 * - 가상메모리 범위의 page table level의 entry를 초기화 한다.
 *   현재 SWAPPER_PGTABLE_LEVELS은 3이므로 PGD, PMD, PTE만을 초기화 하게 된다.
 *   실제로는 PGD, PUD, PMD이지만 code의 통일성을 위해 PGD, PMD, PTE로 되어있다.
 *
 *   code(실제) | shift
 *   ---------------
 *   PGD(PGD)   : 39
 *   PMD(PUD)   : 30
 *   PTE(PMD)   : 21
 *
 *   bic : bic A, B, #C ==> A = (B & ~C)
 *
 *   PTE을 봣을때 다른것과 다르게 compute_indices와 populate_entries사이에
 *   bic를 수행하는데 혹시 모르니 2MB align을 맞추기 위한 것으로 보인다.
 */
/*
 * Map memory for specified virtual address range. Each level of page table needed supports
 * multiple entries. If a level requires n entries the next page table level is assumed to be
 * formed from n pages.
 *
 *	tbl:	location of page table
 *	rtbl:	address to be used for first level page table entry (typically tbl + PAGE_SIZE)
 *	vstart:	start address to map
 *	vend:	end address to map - we map [vstart, vend]
 *	flags:	flags to use to map last level entries
 *	phys:	physical address corresponding to vstart - physical memory is contiguous
 *	pgds:	the number of pgd entries
 *
 * Temporaries:	istart, iend, tmp, count, sv - these need to be different registers
 * Preserves:	vstart, vend, flags
 * Corrupts:	tbl, rtbl, istart, iend, tmp, count, sv
 */
	.macro map_memory, tbl, rtbl, vstart, vend, flags, phys, pgds, istart, iend, tmp, count, sv
/*
 * IAMROOT, 2021.08.24:
 * PGD->PUD(or PMD, when SWAPPER_PGTABLE_LEVELS <= 3) 매핑 시작.
 * PGD, PUD, PMD의 flags가 전부 PMD_TYPE_TABLE 인 것에 주목.
 * 해당 page table entry는 section (실제 값)이 아니라 table이라는 것을 나타낸다.
 */
	add \rtbl, \tbl, #PAGE_SIZE
	mov \sv, \rtbl
	mov \count, #0
	compute_indices \vstart, \vend, #PGDIR_SHIFT, \pgds, \istart, \iend, \count
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
	mov \sv, \rtbl

/*
 * IAMROOT, 2021.08.24:
 * PUD->PMD 매핑 시작.
 */
#if SWAPPER_PGTABLE_LEVELS > 3
	compute_indices \vstart, \vend, #PUD_SHIFT, #PTRS_PER_PUD, \istart, \iend, \count
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
	mov \sv, \rtbl
#endif

/*
 * IAMROOT, 2021.08.24:
 * PMD->PTE 매핑 시작.
 */
#if SWAPPER_PGTABLE_LEVELS > 2
	compute_indices \vstart, \vend, #SWAPPER_TABLE_SHIFT, #PTRS_PER_PMD, \istart, \iend, \count
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
#endif

/*
 * IAMROOT, 2021.08.24:
 * PTE->Section 매핑 시작.
 * flags에 SWAPPER_MM_MMUFLAGS가 들어가는 것에 주목.
 * SWAPPER_MM_MMUFLAGS는 section type이다.
 */
	compute_indices \vstart, \vend, #SWAPPER_BLOCK_SHIFT, #PTRS_PER_PTE, \istart, \iend, \count
/*
 * IAMROOT, 2021.08.28:
 * count는 마지막 단계에서 더 이상 사용하지 않으므로 2MB 단위 정렬 후 rtbl에 사용한다.
 */
	bic \count, \phys, #SWAPPER_BLOCK_SIZE - 1
	populate_entries \tbl, \count, \istart, \iend, \flags, #SWAPPER_BLOCK_SIZE, \tmp
	.endm

/*
 * Setup the initial page tables. We only setup the barest amount which is
 * required to get the kernel running. The following sections are required:
 *   - identity mapping to enable the MMU (low address, TTBR0)
 *   - first few MB of the kernel linear mapping to jump to once the MMU has
 *     been enabled
 */
SYM_FUNC_START_LOCAL(__create_page_tables)
	mov	x28, lr

	/*
	 * Invalidate the init page tables to avoid potential dirty cache lines
	 * being evicted. Other page tables are allocated in rodata as part of
	 * the kernel image, and thus are clean to the PoC per the boot
	 * protocol.
	 */
/*
 * IAMROOT, 2021.08.14:
 * 커널용 페이지 테이블에 대한 캐시를 모두 invalidate
 *
 * - adrp 명령어를 사용한 이유
 *   init_pg_dir은 link script에 의해 주소가 페이지 크기만큼 정렬된다.
 *   그러므로 하위 12 bits를 추가로 처리하는 adr_l 대신 adrp 명령어로도
 *   커버가 가능하다.
 * - 페이지 크기가 4K가 아니면?
 *   16K, 64K 모두 4의 배수이므로 4K 페이지 처리 명령어인 adrp로도 가능하다.
 *
 * - arch/arm64/kernel/vmlinux.lds.S
 *
 *   . = ALIGN(PAGE_SIZE);
 *   init_pg_dir = .;
 *   . += INIT_DIR_SIZE;
 *   init_pg_end = .;
 *
 * - 위에서 보는 것 처럼 init_pg_dir는 PAGE_SIZE로 align되어 있다. 따라서
 *   adrp 명령어로 주소를 가져올 수 있다. 마찬가지로, init_pg_end의 경우도
 *   INIT_DIR_SIZE가 PAGE_SIZE의 배수이기 때문에 init_pg_end도 PAGE_SIZE의
 *   배수가 되므로 adrp 명령어로 주소를 가져올 수 있다.
 *
 * - 그러나 아래의 __idmap_text_end의 경우처럼 PAGE_SIZE의 배수가 보장되지
 *   않는 경우에는 adr_l 명령어를 사용하여 하위 12 bits까지 가져올 수 있도록
 *   한다.
 */
	adrp	x0, init_pg_dir
	adrp	x1, init_pg_end
	sub	x1, x1, x0
	bl	__inval_dcache_area

	/*
	 * Clear the init page tables.
	 */
/*
 * IAMROOT, 2021.08.14: 커널용 페이지 테이블을 0으로 모두 초기화한다.
 */
	adrp	x0, init_pg_dir
	adrp	x1, init_pg_end
	sub	x1, x1, x0
1:	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	subs	x1, x1, #64
	b.ne	1b

/*
 * IAMROOT, 2021.08.14: 커널 매핑에 필요한 디폴트 속성값을 가져온다.
 *
 * 디폴트 속성값을 요약하면 다음과 같다.
 * - Normal memory
 * - Section type
 * - Access Flag
 * - Inner Share
 */
	mov	x7, SWAPPER_MM_MMUFLAGS

	/*
	 * Create the identity mapping.
	 */
	adrp	x0, idmap_pg_dir
	adrp	x3, __idmap_text_start		// __pa(__idmap_text_start)

/*
 * IAMROOT, 2021.08.14: 
 * - mmfr2_el1.lva (1=52bits va support, 0=none support(48))
 *
 * - 런타임에 64K 페이지 사용 시 최대 52비트 매핑 또는 48비트 매핑을 결정한다.
 *   -  4K, 48bits -> VA_BITS_MIN=48, vabits_actual=48
 *   - 64K, 52bits -> VA_BITS_MIN=48, vabits_actual=52(lva support) or 48
 */

#ifdef CONFIG_ARM64_VA_BITS_52
	mrs_s	x6, SYS_ID_AA64MMFR2_EL1
	and	x6, x6, #(0xf << ID_AA64MMFR2_LVA_SHIFT)
	mov	x5, #52
	cbnz	x6, 1f
#endif
	mov	x5, #VA_BITS_MIN
1:
	adr_l	x6, vabits_actual
	str	x5, [x6]
	dmb	sy
	dc	ivac, x6		// Invalidate potentially stale cache line

	/*
	 * VA_BITS may be too small to allow for an ID mapping to be created
	 * that covers system RAM if that is located sufficiently high in the
	 * physical address space. So for the ID map, use an extended virtual
	 * range in that case, and configure an additional translation level
	 * if needed.
	 *
	 * Calculate the maximum allowed value for TCR_EL1.T0SZ so that the
	 * entire ID map region can be mapped. As T0SZ == (64 - #bits used),
	 * this number conveniently equals the number of leading zeroes in
	 * the physical address of __idmap_text_end.
	 */
/*
 * IAMROOT, 2021.08.14: 
 * - VA 확장이 필요한지 점검한다.
 *   __idmap_text_end의 주소를 물리주소로 알아와서 이 주소의 선두 비트들이 0인
 *   개수를 알아와서 TCR_T0SZ(VA_BITS=예:39)=25와 비교한다.
 *   비교하여 물리 주소에 사용한 0이 더 많은 경우 가상 주소 크기가 충분하다.
 *   이 경우 가상 주소 영역의 확장이 필요 없으니  1f 레이블로 이동한다.
 *   확장이 필요한 경우 __idmap_text_end 물리주소에서 산출된 선두 0의 개수를
 *   idmap_t0sz에 저장한다.
 */
	adrp	x5, __idmap_text_end
	clz	x5, x5
	cmp	x5, TCR_T0SZ(VA_BITS)	// default T0SZ small enough?
	b.ge	1f			// .. then skip VA range extension

	adr_l	x6, idmap_t0sz
	str	x5, [x6]
	dmb	sy
	dc	ivac, x6		// Invalidate potentially stale cache line
/*
 * IAMROOT, 2021.08.21:
 * - VA < 48
 *   table table level 을 확장.
 * - VA >= 48
 *   table table을 늘리기만 하는데 PGD table을
 *   PHYS_MASK_SHIFT - PGDIR_SHIFT만큼 늘렸다.
 *   (48 - 39 = 2^9 = 512)
 */
#if (VA_BITS < 48)
#define EXTRA_SHIFT	(PGDIR_SHIFT + PAGE_SHIFT - 3)
#define EXTRA_PTRS	(1 << (PHYS_MASK_SHIFT - EXTRA_SHIFT))

	/*
	 * If VA_BITS < 48, we have to configure an additional table level.
	 * First, we have to verify our assumption that the current value of
	 * VA_BITS was chosen such that all translation levels are fully
	 * utilised, and that lowering T0SZ will always result in an additional
	 * translation level to be configured.
	 */
#if VA_BITS != EXTRA_SHIFT
#error "Mismatch between VA_BITS and page size/number of translation levels"
#endif

	mov	x4, EXTRA_PTRS
	/*
	 * IAMROOT, 2021.08.28:
	 * VA_BITS 가 39라고 가정
	 *
	 * tbl  : x0 -> idmap_pg_dir
	 * virt : x3 -> __idmap_text_start
	 * shift : EXTRA_SHIFT -> 30 + 12 - 3 = 39
	 * ptrs : EXTRA_PTRS -> 2^(9) = 512
	 * x5, x6 : temp
	 */
	create_table_entry x0, x3, EXTRA_SHIFT, x4, x5, x6
#else
	/*
	 * If VA_BITS == 48, we don't have to configure an additional
	 * translation level, but the top-level table has more entries.
	 */
	mov	x4, #1 << (PHYS_MASK_SHIFT - PGDIR_SHIFT)
	str_l	x4, idmap_ptrs_per_pgd, x5
#endif
1:

	ldr_l	x4, idmap_ptrs_per_pgd
	mov	x5, x3				// __pa(__idmap_text_start)
	adr_l	x6, __idmap_text_end		// __pa(__idmap_text_end)
/*
 * IAMROOT, 2021.08.21:
 *   ---
 *   .macro map_memory, tbl, rtbl, vstart, vend, flags, phys, pgds,
 *   istart, iend, tmp, count, sv
 *
 *   idmap은 va == pa라는것을 유념
 *
 *         | dir | corrupt  | idmap                         | init_pg_dir
 *  tbl    | i/o | corrupt  | x0 : __pa(idmap_pg_dir)       | x0 : __pa(init_pg_dir)
 *  rtbl   | o   | corrupt  | x1 : temp register            | x1 : temp register
 *  vstart | i   | preserve | x3 : __pa(__idmap_text_start) | x5 : __va(_text)(= KIMAGE_VADDR) + KASLR
 *  vend   | i   | preserve | x6 : __pa(__idmap_text_end)   | x6 : __va(_end)
 *  flags  | i   | preserve | x7 : SWAPPER_MM_MMUFLAGS
 *  phys   | i   | preserve | x3 : __pa(__idmap_text_start) | x3 : __pa(_text)
 *  pgds   | i   | preserve | x4 : idmap_ptrs_per_pgd       | x4 : PTRS_PER_PGD
 *  ---------------------------------------------------------------------------
 *  istart | o   | corrupt  | x10 : vstart에 대응하는 table index
 *  iend   | o   | corrupt  | x11 : vend에 대응하는 table index
 *  tmp    | o   | corrupt  | x12 : 내부 계산용
 *  count  | io  | corrupt  | x13 : extra count(iend - istart)
 *  sv     | o   | corrupt  | x14 : 내부 계산용
 *
 *   x10부터는 temp register.
 *   ---
 *
 * - idmap table 크기와 init_pg_dir table크기를 집고 넘어가보면
 *   둘다 compile time에 크기가 정해지고 idmap table이 init_pg_dir에 비해
 *   상대적으로 작은 size를 가진다.
 *
 * IAMROOT, 2021.08.24:
 * Identity Mapping 시작.
 *
 * x0: __pa(idmap_pg_dir)
 * x1: temp register
 * x3: __pa(__idmap_text_start)
 * x6: __pa(__idmap_text_end)
 * x7: SWAPPER_MM_MMUFLAGS
 * x3: __pa(__idmap_text_start)
 * x4: idmap_ptrs_per_pgd
 * x10 ~ x14: temp register
 */
	map_memory x0, x1, x3, x6, x7, x3, x4, x10, x11, x12, x13, x14

	/*
	 * Map the kernel image (starting with PHYS_OFFSET).
	 */
	adrp	x0, init_pg_dir
	mov_q	x5, KIMAGE_VADDR		// compile time __va(_text)
	add	x5, x5, x23			// add KASLR displacement
	mov	x4, PTRS_PER_PGD
/*
 * IAMROOT, 2021.08.21:
 * - kernel의 가상주소의 vend를 구해야한다.
 *   vstart는 바로위 코드 x5를 통해 구했고.
 *   _end(가상주소)를 x6으로 adrp를 통해 물리 주소를 알아온다.
 *   _text(가상주소)를 x3으로 adrp를 통해 물리 주소로 알아온다.
 *   x3과 x6의 차이는 kernel이미지의 크기이미지이므로,
 *   kernel 가상주소 start은 x5에 해당 크기를 더하면
 *   kernel 가상주소의 end값이 구해진다.(x6)
 */
	adrp	x6, _end			// runtime __pa(_end)
	adrp	x3, _text			// runtime __pa(_text)
	sub	x6, x6, x3			// _end - _text
	add	x6, x6, x5			// runtime __va(_end)

/*
 * IAMROOT, 2021.08.24:
 * Linear Mapping 시작.
 *
 * x0: __pa(init_pg_dir)
 * x1: temp register
 * x5: __va(_text)
 * x6: __va(_end)
 * x7: SWAPPER_MM_MMUFLAGS
 * x3: __pa(_text)
 * x4: PTRS_PER_PGD
 * x10 ~ x14: temp register
 *
 * > 연습문제
 *  vend  : 0xffff_0000_11f3_f000
 * vstart : 0xffff_0000_1008_0000
 * ------------------------------
 * = 0x01eb_f000 (kimage size: 32MB)
 *
 * - PGD: shift(39), ptrs(512), count(0)
 *   iend   = vend   >> 39 = 0x01ff_fe00 & 0x2ff(ptrs) = 0x0100
 *   iend  += count * ptrs = 0
 *   istart = vstart >> 39 = 0x01ff_fe00 & 0x2ff       = 0x0100
 *   count  = iend - istart = 0
 *   PGD table: 0x100번 엔트리만 사용
 *
 * - PUD: shift(30), ptrs(512), count(0)
 *   iend   = vend   >> 30 = 0xfffc_0000 & 0x2ff = 0x0000
 *   iend  += count * ptrs = 0
 *   istart = vstart >> 30 = 0xfffc_0000 & 0x2ff = 0x0000
 *   count  = iend - istart = 0
 *   PUD table: 0번 엔트리만 사용
 *
 * - PMD: shift(21), ptrs(512), count(0)
 *   iend   = vend   >> 21 = 0xf800_008f & 0x2ff = 0x008f
 *   iend  += count * ptrs = 0
 *   istart = vstart >> 21 = 0xf800_0080 & 0x2ff = 0x0080
 *   count  = iend - istart = 15
 *   PMD table: 0x80 ~ 0x8f번까지의 엔트리만 사용
 *
 * 최종 엔트리들이 가르키는 것은 2MB 단위로 정렬된 블럭
 */
	map_memory x0, x1, x5, x6, x7, x3, x4, x10, x11, x12, x13, x14
/*
 * IAMROOT, 2021.08.21:
 * - 위에 명령어들은 결국 load/store이고 해당 명령어들이 전부 완료되게
 *   알려주는 역할
 */
	/*
	 * Since the page tables have been populated with non-cacheable
	 * accesses (MMU disabled), invalidate those tables again to
	 * remove any speculatively loaded cache lines.
	 */
	dmb	sy
/*
 * IAMROOT, 2021.08.21:
 * - 위에서 memory mapping을 다했으므로 해당 memory의 cache를 전부 한번
 *   정리해주는 코드
 */
	adrp	x0, idmap_pg_dir
	adrp	x1, idmap_pg_end
	sub	x1, x1, x0
	bl	__inval_dcache_area

	adrp	x0, init_pg_dir
	adrp	x1, init_pg_end
	sub	x1, x1, x0
	bl	__inval_dcache_area

	ret	x28
SYM_FUNC_END(__create_page_tables)

/*
 * The following fragment of code is executed with the MMU enabled.
 *
 *   x0 = __PHYS_OFFSET
 */
SYM_FUNC_START_LOCAL(__primary_switched)
	adrp	x4, init_thread_union
	add	sp, x4, #THREAD_SIZE
	adr_l	x5, init_task
	msr	sp_el0, x5			// Save thread_info

#ifdef CONFIG_ARM64_PTR_AUTH
	__ptrauth_keys_init_cpu	x5, x6, x7, x8
#endif

	adr_l	x8, vectors			// load VBAR_EL1 with virtual
	msr	vbar_el1, x8			// vector table address
	isb

	stp	xzr, x30, [sp, #-16]!
	mov	x29, sp

#ifdef CONFIG_SHADOW_CALL_STACK
	adr_l	scs_sp, init_shadow_call_stack	// Set shadow call stack
#endif

	str_l	x21, __fdt_pointer, x5		// Save FDT pointer

	ldr_l	x4, kimage_vaddr		// Save the offset between
	sub	x4, x4, x0			// the kernel virtual and
	str_l	x4, kimage_voffset, x5		// physical mappings

	// Clear BSS
	adr_l	x0, __bss_start
	mov	x1, xzr
	adr_l	x2, __bss_stop
	sub	x2, x2, x0
	bl	__pi_memset
	dsb	ishst				// Make zero page visible to PTW

#ifdef CONFIG_KASAN
	bl	kasan_early_init
#endif
#ifdef CONFIG_RANDOMIZE_BASE
	tst	x23, ~(MIN_KIMG_ALIGN - 1)	// already running randomized?
	b.ne	0f
	mov	x0, x21				// pass FDT address in x0
	bl	kaslr_early_init		// parse FDT for KASLR options
	cbz	x0, 0f				// KASLR disabled? just proceed
	orr	x23, x23, x0			// record KASLR offset
	ldp	x29, x30, [sp], #16		// we must enable KASLR, return
	ret					// to __primary_switch()
0:
#endif
	add	sp, sp, #16
	mov	x29, #0
	mov	x30, #0
	b	start_kernel
SYM_FUNC_END(__primary_switched)

	.pushsection ".rodata", "a"
SYM_DATA_START(kimage_vaddr)
	.quad		_text
SYM_DATA_END(kimage_vaddr)
EXPORT_SYMBOL(kimage_vaddr)
	.popsection

/*
 * end early head section, begin head code that is also used for
 * hotplug and needs to have the same protections as the text region
 */
	.section ".idmap.text","awx"

/*
 * If we're fortunate enough to boot at EL2, ensure that the world is
 * sane before dropping to EL1.
 *
 * Returns either BOOT_CPU_MODE_EL1 or BOOT_CPU_MODE_EL2 in w0 if
 * booted in EL1 or EL2 respectively.
 */

SYM_FUNC_START(el2_setup)
	msr	SPsel, #1			// We want to use SP_EL{1,2}
/*
 * IAMROOT, 2021.07.24:
 * - SPsel: 커널 진입 시 EL1, EL2 로 부팅이 되고,
 *          부팅 되었던 Exception Level 의 Stack 선택한다.
 */
	mrs	x0, CurrentEL
/*
 * IAMROOT, 2021.07.24:
 * - 현재 EL 을 x0 로 가져온다.
 */
	cmp	x0, #CurrentEL_EL2
/*
 * IAMROOT, 2021.07.24:
 * - CurrentEL_EL2 는 8 로 정의됨
 */
	b.eq	1f
/*
 * IAMROOT, 2021.07.24:
 * - CurrentEL_EL1 실행되는 코드
 */
	mov_q	x0, (SCTLR_EL1_RES1 | ENDIAN_SET_EL1)
	msr	sctlr_el1, x0
/*
 * IAMROOT, 2021.07.24:
 * - SCTLR_EL1_RES1: SCTLR 예약 비트(RES1) 5개
 * - ENDIAN_SET_EL1: Endian 설정
 *   -> CONFIG_CPU_BIG_ENDIAN가 true이면 big endian, 아니면 little endian이다.
 */
	mov	w0, #BOOT_CPU_MODE_EL1		// This cpu booted in EL1

	isb
/*
 * IAMROOT, 2021.07.24:
 * - isb: Instruction Synchronization Barrier.
 *   파이프라인을 비운다.
 *   엔디안 설정이 끝나면 파이프라인을 비워서
 *   바뀐 엔디안으로 실행되도록 한다.
 */
	ret

/*
 * IAMROOT, 2021.08.13:
 * - 현재 Exception Level은 EL2.
 * - SCTLR_EL2_RES1: SCTLR 예약 비트(RES1) 9개
 * - ENDIAN_SET_EL2: Endian 설정
 *   -> CONFIG_CPU_BIG_ENDIAN가 true이면 big endian, 아니면 little endian이다.
 */
1:	mov_q	x0, (SCTLR_EL2_RES1 | ENDIAN_SET_EL2)
	msr	sctlr_el2, x0

/*
 * IAMROOT, 2021. 07. 31:
 *   VHE : Virtualization host extensions
 *   이전에는 부팅을 EL2에서 커널 실행은 EL1
 *   VHE는 EL2에서 커널이 실행 됨
 *   사용 목적은 world switch를 줄임으로써
 *   kvm 가속을 빠르게 하기 위해서 사용함
 */
#ifdef CONFIG_ARM64_VHE
	/*
	 * Check for VHE being present. For the rest of the EL2 setup,
	 * x2 being non-zero indicates that we do have VHE, and that the
	 * kernel is intended to run at EL2.
	 */
/*
 * IAMROOT, 2021. 07. 31:
 * - VHE 기능이 있는지 없는지 확인(x2: 0=none, 1=support)
 * - id registers: 4bit id 필드로 기능에 대한 내용
 * - VHE 기능이 있으면 x2 = 1.
 * - VHE 기능이 없으면 x2 = 0.
 */
	mrs	x2, id_aa64mmfr1_el1
	ubfx	x2, x2, #ID_AA64MMFR1_VHE_SHIFT, #4
#else
	mov	x2, xzr
#endif

	/* Hyp configuration. */
	mov_q	x0, HCR_HOST_NVHE_FLAGS
	cbz	x2, set_hcr
	mov_q	x0, HCR_HOST_VHE_FLAGS
set_hcr:
	msr	hcr_el2, x0
	isb

	/*
	 * Allow Non-secure EL1 and EL0 to access physical timer and counter.
	 * This is not necessary for VHE, since the host kernel runs in EL2,
	 * and EL0 accesses are configured in the later stage of boot process.
	 * Note that when HCR_EL2.E2H == 1, CNTHCTL_EL2 has the same bit layout
	 * as CNTKCTL_EL1, and CNTKCTL_EL1 accessing instructions are redefined
	 * to access CNTHCTL_EL2. This allows the kernel designed to run at EL1
	 * to transparently mess with the EL0 bits via CNTKCTL_EL1 access in
	 * EL2.
	 */
/* 
 * IAMROOT-18, 2021.07.31
 * - nVHE로 동작할 때, cnthctl_el2의 physical timer & counter를 enable 시킴.
 *   커널이 EL2-VHE로 동작 시 마치 EL1으로 동작하는 것과 같게 만드는 것을 보장하는 코드.
 */
	cbnz	x2, 1f
	mrs	x0, cnthctl_el2
	orr	x0, x0, #3			// Enable EL1 physical timers
	msr	cnthctl_el2, x0
1:
/* IAMROOT, 2021.08.07:
 * 64-bit virtual offset을 가지고 있으며 voff 값은 Guest OS에서 사용할
 * Virtual Counter 값을 계산하는데 이용. 
 *
 *   Physical Counter 
 * - voffset
 * ----------
 *   Virtual Counter -> Guest OS에서 사용
 */
	msr	cntvoff_el2, xzr		// Clear virtual offset

#ifdef CONFIG_ARM_GIC_V3
	/* GICv3 system register access */
/* IAMROOT, 2021.08.07:
 * PE에 구현된 기능에 대해 정보 제공
 * ID_AA64_*: 지원 기능들을 4bit 단위로 제공함을 의미
 */
	mrs	x0, id_aa64pfr0_el1
/* IAMROOT, 2021.08.07:
 * GIC: GIC 시스템 레지스터 인터페이스 제공 여부
 * - 0b0000: GIC 인터페이스 제공(X), Memory-mapped 방식 이용
 * - 0b0001: v3/4 버전 인터페이스 사용
 * - 0b0011: v4.1 버전 인터페이스 사용
 */
	ubfx	x0, x0, #ID_AA64PFR0_GIC_SHIFT, #4
	cbz	x0, 3f

/* IAMROOT, 2021.08.07:
 * EL2에서 사용하는 GIC 시스템 레지스터를 enable 하기위한 레지스터
 *
 * - SRE: System Register Enable
 *   0x0: Memory-mapped 이용
 *   0x1: GIC 시스템 레지스터 이용
 *
 * - ENABLE: EL0에서 ICC_SRE_EL1 reg를 사용하려고 할 때 trap(에러) 발생 여부 의미.
 *   0x0: Non-secure EL1 accesses to ICC_SRE_EL1 trap to EL2
 *        EL2로 trap 한다는 의미는 시스템 에러로 판단하고 동작이 안되도록 만듬.
 *   0x1: Non-secure EL1 accesses to ICC_SRE_EL1 do not trap to EL2
 *        trap 하지 않는다는 의미는 EL2가 ICC_SRE_EL1에 접근할 수 있음을 의미.
 *
 *   elseif EL2Enabled() && ICC_SRE_EL2.Enable == '0' then
 *      AArch64.SystemAccessTrap(EL2, 0x18);
 *   ...
 *   return ICC_SRE_EL1;
 *
 * - RAO/WI type bit:
 *   해당 bit 값을 항상 1로 읽음 (쓰기는 항상 무시)
 *   (Read as One, Write Ignored):
 */
	mrs_s	x0, SYS_ICC_SRE_EL2
	orr	x0, x0, #ICC_SRE_EL2_SRE	// Set ICC_SRE_EL2.SRE==1
	orr	x0, x0, #ICC_SRE_EL2_ENABLE	// Set ICC_SRE_EL2.Enable==1
	msr_s	SYS_ICC_SRE_EL2, x0
	isb					// Make sure SRE is now set
/* IAMROOT, 2021.08.07:
 * ICC_SRE_EL2의 SRE(0bit)를 다시 읽고 체크하여 0이면 초기화가 되지
 * 않았으므로 레이블 3으로 점프
 *
 * TBZ: test #<imm> bit and branch if zero
 */
	mrs_s	x0, SYS_ICC_SRE_EL2		// Read SRE back,
	tbz	x0, #0, 3f			// and check that it sticks
/* IAMROOT, 2021.08.07:
 * Hypervisor에서 사용하는 GIC용 Hyper control 레지스터 값 초기화
 * ICH_*: per-cpu 레지스터
 */
	msr_s	SYS_ICH_HCR_EL2, xzr		// Reset ICC_HCR_EL2 to defaults

3:
#endif

	/* Populate ID registers. */
/* IAMROOT, 2021.08.07:
 * midr: PE에 대한 ID 정보 제공.
 * - SoC Vendor
 * - Architecture
 * - Variant: 하위 SoC에 의해 몇가지 변경된 제품에서 사용 
 * - PartNum: 하위 SoC에 의해 몇가지 변경된 제품에서 사용
 * - Rev.
 *
 *  Implementation Defined: ARM이 아닌 SoC들이 설정할 수 있는 비트 필드.
 * !Implementation Defined: Global로서 ARM이 설정해놓는 비트 필드.
 *
 * mpidr: Multiprocessor Affinity Register
 * Scheduling 목적으로 사용되는 Core ID 정보 제공.
 * - per-cpu로 존재하는 시스템 레지스터이며 cpu 마다 다른값(Core Number)을 가짐.
 *   이 값들은 S/W Scheduling에 사용되며 CPU/Cluster를 구분하는데 사용.
 *
 * MT(bit): Hyper-threading 관련
 *   * MT 0:
 *     - aff0: Core Number
 *             (rasp4: per-cpu aff0에 0, 1, 2, 3이 들어있음)
 *     - aff1: Cluster에 대한 정보
 *     - aff2: Cluster 단계에서 더 높은 레벨
 *   * MT 1:
 *     - aff0: H/W Thread Number
 *     - aff1: Core Number
 *     - aff2: Cluster에 대한 정보
 *     - aff3: Cluster 단계에서 더 높은 레벨
 */
	mrs	x0, midr_el1
	mrs	x1, mpidr_el1
/*
 * IAMROOT, 2021.08.07:
 * 위 정보들을 Hypervisor 시스템 레지스터에 저장
 *
 * Trap을 이용해서 operation을 virtualize하는 것은 많은 비용이 든다.
 * Feature register들, 예를 들어 ID_AA64MMFR0_EL1 처럼 OS에 의해 자주
 * 접근되지 않는 레지스터는 크게 상관 없지만 MIDR_EL1, MPIDR_EL1같이
 * 자주 접근되는 레지스터들에 접근하는 operation들에게는 부담이 된다.
 *
 * 이를 개선하기 위해서 Guest OS가 해당 operation을 수행하기 위해서
 * Hypervisor에 일일이 Trap을 날리기 보다는 virtual value를 보도록
 * 하는 방법을 사용하기도 한다.
 *
 *  VPIDR_EL2: EL1이 MIPDR_EL1을 읽으면 Trap없이 하드웨어가 자동으로
 *             VPIDR_EL2 값을 돌려준다.
 *
 * VMPIDR_EL2: EL1이 MPIPDR_EL1을 읽으면 Trap없이 하드웨어가 자동으로
 *             VMPIDR_EL2 값을 돌려준다.
 */
	msr	vpidr_el2, x0
	msr	vmpidr_el2, x1
/* IAMROOT, 2021.08.07:
 * 32-bit EL0에서 동작하는 S/W 기능을 64-bit 시스템에서도 동작할 수 있도록
 * 기능 Enable.
 *
 * - user helper:
 *   Syscall로는 느리지만 Kernel Func를 빠르게 접근할 수 있는 특수 기능
 *   - Timer-counter (빠르게 처리해야 함)
 *   - Barrier
 *   - 32bit에서'만' 지원하는 코드 (제약이 많은 32bit 시스템에서 사용)
 * - VFP: Vector Floating Point
 */
#ifdef CONFIG_COMPAT
    /* IAMROOT, 2021.08.07:
     * 32-bit S/W의 경우 CP15를 접근하는 부분이 있으므로 AARCH32 EL0, EL1이
     * System Register에 접근할 시 EL2로 trap하는 것을 disable.
     */
	msr	hstr_el2, xzr			// Disable CP15 traps to EL2
#endif

/* IAMROOT, 2021.08.07: NO */
	/* EL2 debug */
	mrs	x1, id_aa64dfr0_el1
	sbfx	x0, x1, #ID_AA64DFR0_PMUVER_SHIFT, #4
	cmp	x0, #1
	b.lt	4f				// Skip if no PMU present
	mrs	x0, pmcr_el0			// Disable debug access traps
	ubfx	x0, x0, #11, #5			// to EL2 and allow access to
4:
	csel	x3, xzr, x0, lt			// all PMU counters from EL1

	/* Statistical profiling */
	ubfx	x0, x1, #ID_AA64DFR0_PMSVER_SHIFT, #4
	cbz	x0, 7f				// Skip if SPE not present
	cbnz	x2, 6f				// VHE?
	mrs_s	x4, SYS_PMBIDR_EL1		// If SPE available at EL2,
	and	x4, x4, #(1 << SYS_PMBIDR_EL1_P_SHIFT)
	cbnz	x4, 5f				// then permit sampling of physical
	mov	x4, #(1 << SYS_PMSCR_EL2_PCT_SHIFT | \
		      1 << SYS_PMSCR_EL2_PA_SHIFT)
	msr_s	SYS_PMSCR_EL2, x4		// addresses and physical counter
5:
	mov	x1, #(MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT)
	orr	x3, x3, x1			// If we don't have VHE, then
	b	7f				// use EL1&0 translation.
6:						// For VHE, use EL2 translation
	orr	x3, x3, #MDCR_EL2_TPMS		// and disable access from EL1
7:
	msr	mdcr_el2, x3			// Configure debug traps
/* IAMROOT, 2021.08.07: NO */

/* IAMROOT, 2021.08.07: 
 * LORegion: Limited Ordering Region 어드레스 범위를 오더링 제한
 * LO [19:16] 
 * 0x1 LoReigion Supported
 * 
 * LORC : LOR control
 * DS [3:2]
 * LORSA_EL1, LOREA_EL1 시작과 끝의 범위를 지정
 * EN [0]
 * Enable 1 , disable 0
 */
	/* LORegions */
	mrs	x1, id_aa64mmfr1_el1
	ubfx	x0, x1, #ID_AA64MMFR1_LOR_SHIFT, 4
	cbz	x0, 1f
    /*
     * IAMROOT, 2021.08.14
     * 만약 LORegion Feature가 implement되있으면
     * LORegion을 disable시킨다.
     */
	msr_s	SYS_LORC_EL1, xzr
1:
/* IAMROOT, 2021.08.07: 
 * TTBR0_EL2 
 *   하이퍼바이저가 사용
 * VTTBR0_EL2 
 *   Guest OS(또는 application EL0) 에서 진짜 주소로 변환하는 과정에서 
 *   stage1과 stage2를 거쳐 physical memory를 받음, 이 때 stage2에서 사용
 *   TTBR0_EL1은 stage1에서 사용
 *
 * TTBR & VTTBR 현재 돌아가는 운영체제와 에플리케이션을 look up할 때 사용
 * TTBR의 ASID(운영체제), VTTBR의 VMID(애플리케이션)
 */
	/* Stage-2 translation */
	msr	vttbr_el2, xzr

/* IAMROOT, 2021.08.07: 
 * x2: VHE가 서포트 되는지 않되는지
 *   - 1: VHE, 0: nVHE
 *
 * w0 - x0의 하위 32bit
 * BOOT_CPU_MODE_EL2 == 0xe12
 * 
 * isb(instruction syncronization barrier)
 *   파이프라인 비워줌
 */
	cbz	x2, install_el2_stub
	mov	w0, #BOOT_CPU_MODE_EL2		// This CPU booted in EL2
	isb
	ret

/* IAMROOT, 2021.08.07: 
 * SYM_L_LOCAL 왜 LOCAL을 넣었는지
 *   컴파일러에게 일러줌 (불필요한 메모리 낭비를 줄이기 위해LOCAL) 
 *   + 이름이 겹쳐도 상관없게
 *   e.g. link타임에 extern과 같은 심벌로 들어가지 않게
 *
 * install_el2_stub --> stub? 
 *   구현이 제대로 된 큰 코드가 아닌, 조금한 조각
 *   무거운 el2에서 돌다 el1으로 패스하는 역할만
 */
SYM_INNER_LABEL(install_el2_stub, SYM_L_LOCAL)
	/*
	 * When VHE is not in use, early init of EL2 and EL1 needs to be
	 * done here.
	 * When VHE _is_ in use, EL1 will not be used in the host and
	 * requires no configuration, and all non-hyp-specific EL2 setup
	 * will be done via the _EL1 system register aliases in __cpu_setup.
	 */

/* IAMROOT, 2021.08.07: 
 * SCTLR_EL1 - kernel config 값에 따라 Endian이 설정 
 */
	mov_q	x0, (SCTLR_EL1_RES1 | ENDIAN_SET_EL1)
	msr	sctlr_el1, x0

/* IAMROOT, 2021.08.07: 
 * cptr_el2에 0x33ff
 *
 * TFP [10] - 0
 *   Advanced SIMD, Floating-Point 레지스터에 접근시
 *   0b0: trap이 일어나지 않도록, 0b1: trap이 일어나도록
 *
 * TZ [8] - 1 (SVE 명령을 사용할 때)
 *   0b0: trap이 일어나지 않도록, 0b1: trap이 일어나도록 
 * 나머지 비트는 RES1을 1로 
 *
 * SVE: Scalable Vector Extension
 * Z: vector registers(Z0, Z1, ...) -> ZCR: control register.
 */
	/* Coprocessor traps. */
	mov	x0, #0x33ff
	msr	cptr_el2, x0			// Disable copro. traps to EL2

/* IAMROOT, 2021.08.07: 
 * SVE가 내장되어 있는지 확인 후 (어차피 없으면 SVE를 사용하는 어플리케이션이 종료됨)
 * 없다면 branch 
 */
	/* SVE register access */
	mrs	x1, id_aa64pfr0_el1
	ubfx	x1, x1, #ID_AA64PFR0_SVE_SHIFT, #4
	cbz	x1, 7f


/* IAMROOT, 2021.08.07: 
 * cptr_el2의 TZ 클리어
 * 다시 말하면, SVE가 내장되어 있으면 Trap하지 않고 관련 레지스터를 사용하겠다는 의미.
 *
 * ZCR_ELx_LEN_MASK == 0x1ff
 * SYS_ZCR_EL2
 *   SVE를 위해 가장 큰 벡터길이로 활성화시킨다
 * LEN [3:0]
 *   이때 길이는 (LEN+1)x128 bits 
 */
	bic	x0, x0, #CPTR_EL2_TZ		// Also disable SVE traps
	msr	cptr_el2, x0			// Disable copro. traps to EL2
	isb
	mov	x1, #ZCR_ELx_LEN_MASK		// SVE: Enable full vector
	msr_s	SYS_ZCR_EL2, x1			// length for EL1.
  
	/* Hypervisor stub */
/*
 * IAMROOT, 2021.08.14: EL2용 하이퍼 벡터 주소를 vbar_el2 레지스터에 기록
 */

7:	adr_l	x0, __hyp_stub_vectors
	msr	vbar_el2, x0

	/* spsr */
/*
 * IAMROOT, 2021.08.14: EL1으로 돌아갈때 DAIF 플래그들을 모두 설정하여
 *   인터럽트나 정렬 exception이 발생하지 않도록 막는다.
 *    - EL1으로 모드 변경 시 사용할 스택은 EL1용 스택이다.
 */

	mov	x0, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT |\
		      PSR_MODE_EL1h)
	msr	spsr_el2, x0
	msr	elr_el2, lr
	mov	w0, #BOOT_CPU_MODE_EL2		// This CPU booted in EL2
	eret
SYM_FUNC_END(el2_setup)

/*
 * Sets the __boot_cpu_mode flag depending on the CPU boot mode passed
 * in w0. See arch/arm64/include/asm/virt.h for more info.
 */
/*
 * IAMROOT, 2021.08.14: 
 * - w0로 알아온 부트(el1 or el2) 모드 값을 저장한다.
 */
SYM_FUNC_START_LOCAL(set_cpu_boot_mode_flag)
	adr_l	x1, __boot_cpu_mode
	cmp	w0, #BOOT_CPU_MODE_EL2
	b.ne	1f
	add	x1, x1, #4
1:	str	w0, [x1]			// This CPU has booted in EL1
	dmb	sy
	dc	ivac, x1			// Invalidate potentially stale cache line
	ret
SYM_FUNC_END(set_cpu_boot_mode_flag)

/*
 * These values are written with the MMU off, but read with the MMU on.
 * Writers will invalidate the corresponding address, discarding up to a
 * 'Cache Writeback Granule' (CWG) worth of data. The linker script ensures
 * sufficient alignment that the CWG doesn't overlap another section.
 */
	.pushsection ".mmuoff.data.write", "aw"
/*
 * We need to find out the CPU boot mode long after boot, so we need to
 * store it in a writable variable.
 *
 * This is not in .bss, because we set it sufficiently early that the boot-time
 * zeroing of .bss would clobber it.
 */

/*
 * IAMROOT, 2021.08.14: 
 * - 지시어 .long은 4바이트 값이다.
 *   set_cpu_boot_mode_flag 함수가 아래 값을
 *   부팅한 모드(el1 or el2) 값으로 동일해지도록 기록한다.
 *
 * - 해당 데이터는 '.mmuoff.data.write' section에 저장되며 아래 C 코드와
 *   유사한 의미를 가진다. (bss section이 아님에 유의하자)
 *
 *   static int __boot_cpu_mode[] = {
 *      BOOT_CPU_MODE_EL2, BOOT_CPU_MODE_EL1
 *   };
 */
SYM_DATA_START(__boot_cpu_mode)
	.long	BOOT_CPU_MODE_EL2
	.long	BOOT_CPU_MODE_EL1
SYM_DATA_END(__boot_cpu_mode)
/*
 * The booting CPU updates the failed status @__early_cpu_boot_status,
 * with MMU turned off.
 */
SYM_DATA_START(__early_cpu_boot_status)
	.quad 	0
SYM_DATA_END(__early_cpu_boot_status)

	.popsection

	/*
	 * This provides a "holding pen" for platforms to hold all secondary
	 * cores are held until we're ready for them to initialise.
	 */
SYM_FUNC_START(secondary_holding_pen)
	bl	el2_setup			// Drop to EL1, w0=cpu_boot_mode
	bl	set_cpu_boot_mode_flag
	mrs	x0, mpidr_el1
	mov_q	x1, MPIDR_HWID_BITMASK
	and	x0, x0, x1
	adr_l	x3, secondary_holding_pen_release
pen:	ldr	x4, [x3]
	cmp	x4, x0
	b.eq	secondary_startup
	wfe
	b	pen
SYM_FUNC_END(secondary_holding_pen)

	/*
	 * Secondary entry point that jumps straight into the kernel. Only to
	 * be used where CPUs are brought online dynamically by the kernel.
	 */
SYM_FUNC_START(secondary_entry)
	bl	el2_setup			// Drop to EL1
	bl	set_cpu_boot_mode_flag
	b	secondary_startup
SYM_FUNC_END(secondary_entry)

SYM_FUNC_START_LOCAL(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 */
	bl	__cpu_secondary_check52bitva
	bl	__cpu_setup			// initialise processor
	adrp	x1, swapper_pg_dir
	bl	__enable_mmu
	ldr	x8, =__secondary_switched
	br	x8
SYM_FUNC_END(secondary_startup)

SYM_FUNC_START_LOCAL(__secondary_switched)
	adr_l	x5, vectors
	msr	vbar_el1, x5
	isb

	adr_l	x0, secondary_data
	ldr	x1, [x0, #CPU_BOOT_STACK]	// get secondary_data.stack
	cbz	x1, __secondary_too_slow
	mov	sp, x1
	ldr	x2, [x0, #CPU_BOOT_TASK]
	cbz	x2, __secondary_too_slow
	msr	sp_el0, x2
	scs_load x2, x3
	mov	x29, #0
	mov	x30, #0

#ifdef CONFIG_ARM64_PTR_AUTH
	ptrauth_keys_init_cpu x2, x3, x4, x5
#endif

	b	secondary_start_kernel
SYM_FUNC_END(__secondary_switched)

SYM_FUNC_START_LOCAL(__secondary_too_slow)
	wfe
	wfi
	b	__secondary_too_slow
SYM_FUNC_END(__secondary_too_slow)

/*
 * IAMROOT, 2021.08.28:
 * - status를 저장한다.
 *   status가 0이면 정상이다.
 */

/*
 * The booting CPU updates the failed status @__early_cpu_boot_status,
 * with MMU turned off.
 *
 * update_early_cpu_boot_status tmp, status
 *  - Corrupts tmp1, tmp2
 *  - Writes 'status' to __early_cpu_boot_status and makes sure
 *    it is committed to memory.
 */

	.macro	update_early_cpu_boot_status status, tmp1, tmp2
	mov	\tmp2, #\status
	adr_l	\tmp1, __early_cpu_boot_status
	str	\tmp2, [\tmp1]
	dmb	sy
	dc	ivac, \tmp1			// Invalidate potentially stale cache line
	.endm

/*
 * Enable the MMU.
 *
 *  x0  = SCTLR_EL1 value for turning on the MMU.
 *  x1  = TTBR1_EL1 value
 *
 * Returns to the caller via x30/lr. This requires the caller to be covered
 * by the .idmap.text section.
 *
 * Checks if the selected granule size is supported by the CPU.
 * If it isn't, park the CPU
 */
SYM_FUNC_START(__enable_mmu)
/*
 * IAMROOT, 2021.08.28:
 * - Config 에 따른 Granule를 아키텍처가 지원하는지를 확인해서
 *   지원하지 않으면 __no_granule_support에서 무한루프 돌도록 하며
 *   지원하면 정상임을 의미하는 status(0)를 __early_cpu_boot_status에 저장한다.
 *   early startup에서는 H/W debugger 이용하여 status 코드를
 *   확인할 수 있다.
 *
 * -   TGRAN: Translation Granule Size.
 * -  TGRAN4: 4KB TGRAN
 * - TGRAN16: 16KB TGRAN
 * - TGRAN64: 64KB TGRAN
 */
	mrs	x2, ID_AA64MMFR0_EL1
	ubfx	x2, x2, #ID_AA64MMFR0_TGRAN_SHIFT, 4
	cmp	x2, #ID_AA64MMFR0_TGRAN_SUPPORTED
	b.ne	__no_granule_support
	update_early_cpu_boot_status 0, x2, x3
	adrp	x2, idmap_pg_dir
	phys_to_ttbr x1, x1
	phys_to_ttbr x2, x2
/*
 * IAMROOT, 2021.08.28:
 * - ttbr0_el1 : user용이지만 부팅중에는 임시로 idmap으로 사용한다.
 *   ttbr1_el1 : kernel용이며 init_pg_dir을 가리킨다.
 */
	msr	ttbr0_el1, x2			// load TTBR0
/*
 * IAMROOT, 2021.08.28:
 * - TODO
 */
	offset_ttbr1 x1, x3
	msr	ttbr1_el1, x1			// load TTBR1
	isb
/*
 * IAMROOT, 2021.08.28:
 * - SCTLR_EL1에 mmu eanble on이 set되있다.
 *   이 명령어로 mmu enable 및 x0에 세팅되있던 설정들이 on된다.
 */
	msr	sctlr_el1, x0
/*
 * IAMROOT, 2021.09.02:
 * - mmu enable. ARMv8-A-Programmer-Guid에 보면 해당 예제가 나와있다.
 *
 * - page fault 발생여부에 대하여.
 *   idmap.text에 이 code들이 들어잇고, idmap은 ttbr0_el1에서
 *   바로위에서 가리키도록 설정했으며 phy와 1대1매핑인 상태기때문에
 *   mmu가 켜지는즉시 page fault가 안 일어난다.
 */
	isb

/*
 * IAMROOT, 2021.08.28:
 * - I cache 를 PoU까지 모두 invalidate 한다.
 */
	/*
	 * Invalidate the local I-cache so that any instructions fetched
	 * speculatively from the PoC are discarded, since they may have
	 * been dynamically patched at the PoU.
	 */
	ic	iallu
	dsb	nsh
	isb
	ret
SYM_FUNC_END(__enable_mmu)

SYM_FUNC_START(__cpu_secondary_check52bitva)
#ifdef CONFIG_ARM64_VA_BITS_52
	ldr_l	x0, vabits_actual
	cmp	x0, #52
	b.ne	2f

	mrs_s	x0, SYS_ID_AA64MMFR2_EL1
	and	x0, x0, #(0xf << ID_AA64MMFR2_LVA_SHIFT)
	cbnz	x0, 2f

	update_early_cpu_boot_status \
		CPU_STUCK_IN_KERNEL | CPU_STUCK_REASON_52_BIT_VA, x0, x1
1:	wfe
	wfi
	b	1b

#endif
2:	ret
SYM_FUNC_END(__cpu_secondary_check52bitva)

/*
 * IAMROOT, 2021.08.28:
 * - 아키텍처가 지원하지 않은 Granule를 설정하게 할려고 했기때문에
 *   status를 error bit로 설정하고 무한 wait로 들어간다.
 *
 *   후에 하드웨어 디버깅을 할때 해당 변수를 확인하면 무슨 error 보게 하기
 *   위함이다. (해당 변수: __early_cpu_boot_status)
 *
 *   wfe : wait for event
 *   wfi : wait for interrupt
 *   너무 빠르게 계속 동작하지 않게 하기 위함(전력 소비를 줄이기위함)
 */
SYM_FUNC_START_LOCAL(__no_granule_support)
	/* Indicate that this CPU can't boot and is stuck in the kernel */
	update_early_cpu_boot_status \
		CPU_STUCK_IN_KERNEL | CPU_STUCK_REASON_NO_GRAN, x1, x2
1:
	wfe
	wfi
	b	1b
SYM_FUNC_END(__no_granule_support)

#ifdef CONFIG_RELOCATABLE
SYM_FUNC_START_LOCAL(__relocate_kernel)
/*
 * IAMROOT, 2021.08.28:
 * - 그전 까지는 adr, adrp를 사용했었는데 여기는 컴파일 당시에 사용한
 *   절대주소를 사용해야 되기 때문에 ldr을 사용해야한다.
 *   adr을 사용해도 되지만 __rela_offset등의 주소는 0xff..
 *   주소이기 때문에 매우 멀리 떨어져 있어서 ldr을 사용해야 한다.
 */
	/*
	 * Iterate over each entry in the relocation table, and apply the
	 * relocations in place.
	 */
	ldr	w9, =__rela_offset		// offset to reloc table
	ldr	w10, =__rela_size		// size of reloc table

	mov_q	x11, KIMAGE_VADDR		// default virtual offset
/*
 * IAMROOT, 2021.08.28:
 * - x23 : compile time에 계산된 kernel 주소의 2MB 정렬의 나머지값.
 *   보통 0으로 보면된다. randomized가 적용된경우 이 x23이 조금 틀어질수도있다.
 *
 * - relocate start address(x9)
 *   x9 = x23(0) + KIMAGE_VADDR(x11) + __rela_offset(w9)
 *   
 * - relocate end address(x10)
 *   x10 = x9 + __rela_size(w10)
 */
	add	x11, x11, x23			// actual virtual offset
	add	x9, x9, x11			// __va(.rela)
	add	x10, x9, x10			// __va(.rela) + sizeof(.rela)

0:	cmp	x9, x10
	b.hs	1f
/*
 * IAMROOT, 2021.08.28:
 * =====================================================================
 *  - ELF Relocation Table Entry Format
 *  https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-54839.html
 *
 *  +-------------------------------+--------+------+------------+
 *  | Description                   | offset | size | filed name |
 *  +-------------------------------+--------+------+------------+
 *  | Offset used to cacluate reloc | 0x00   | 8    | r_offset   |
 *  | Reloc typing meta-data        | 0x08   | 8    | r_info     |
 *  | Extra argument used in reloc  | 0x10   | 8    | r_addend   |
 *  +-------------------------------+--------+------+------------+
 *
 *  elf 스펙상 현재 Table Entry를 24byte씩 사용한다.
 *  Table 정보에는 offset, type, addend등이 있으며 그중에 type을 비교한다.
 *
 * =====================================================================
 *
 *  다음은 실제 vmlinux의 .rel.dyn section을 72byte만
 *  dump 한 예제이며, 현재 x9는 첫번째줄의 데이터 0번째를
 *  가리키고 있을것이다.
 *
 * -----------------------------------------------------------
 * (x9) 989fdd10 0080ffff 03040000 00000000 3c9cdb10 0080ffff
 *      a09fdd10 0080ffff 03040000 00000000 d86ae010 0080ffff
 *      a89fdd10 0080ffff 03040000 00000000 4058dd10 0080ffff
 * (little endian으로 되있다는것을 고려한다.)
 * (x9 : x9에 저장되있는 주소의 위치)
 * -----------------------------------------------------------
 *
 * 행별로 첫 8byte가 r_offset, 그다음 8byte가 r_info, 그 다음 8byte가 r_addend
 * 가 된다.
 * 
 * x12, x13 register에 어떻게 데이터가 저장되는지 살펴보면
 * (편의상 little endian dump를 그대로 사용한다)
 * 
 * ldp	x12, x13, [x9], #24 이 명령어가 실행되면 첫번쨰줄의
 *
 * -----------------------------------------------------------
 * (x9) 989fdd10 0080ffff 03040000 00000000 3c9cdb10 0080ffff
 * -----------------------------------------------------------
 * 에서
 *
 * x12 = [x9] = 989fdd10 0080ffff
 * x13 = [x9, 8] = 03040000 00000000
 *
 * 이렇게 x12, x13에 데이터가 저장될것이고
 * 3c9cdb10 0080ffff 이 다음이 x9가 될것이다.
 *
 * -----------------------------------------------------------
 *      989fdd10 0080ffff 03040000 00000000 3c9cdb10 0080ffff
 * (x9) a09fdd10 0080ffff 03040000 00000000 d86ae010 0080ffff
 *      a89fdd10 0080ffff 03040000 00000000 4058dd10 0080ffff
 * -----------------------------------------------------------
 *
 * ldr	x14, [x9, #-8] 이 명령어가 실행되면
 * 
 * 3c9cdb10 0080ffff .여기에 x9가 위치하고 있으므로 x9의 -8만큼의 위치는
 * 
 * -----------------------------------------------------------
 *      989fdd10 0080ffff 03040000 00000000 (x9 - 8) 3c9cdb10 0080ffff
 * (x9) a09fdd10 0080ffff 03040000 00000000          d86ae010 0080ffff
 *      a89fdd10 0080ffff 03040000 00000000          4058dd10 0080ffff
 * -----------------------------------------------------------
 *  위와 같을것이다.
 * 
 * 즉 x14엔 3c9cdb10 0080ffff가 저장될것이다.
 * 다시 dump당 x9의 포지션과 x12, x13, x14값을 정리하면 다음과 같다.
 *
 * loop당
 *  |  x9위치 | x12(symbol addr)  | x13(type)         | x14(rel addr)       
 * -------+--------------------+---------------------+-----------------
 * 0|  x9    | 989fdd10 0080ffff | 03040000 00000000 | 3c9cdb10 0080ffff
 * 1|  x9    | a09fdd10 0080ffff | 03040000 00000000 | d86ae010 0080ffff
 * 2|  x9    | a89fdd10 0080ffff | 03040000 00000000 | 4058dd10 0080ffff
 *
 * 그 후 x13을 R_AARCH64_RELATIVE값과 비교해서 해당값과 맞다면
 * (R_AARCH64_RELATIVE의 hex값은 0x403이고 현재 dump는
 * little endian임으로 해당값이랑 일치하고 있다.)
 * 
 * x14에 x23(0, 혹은 조금 틀어진)을 더한후
 * x12 + x23의 주소에 x14값을 넣는, 즉 dynamic relocation이 수행된다.
 *
 * =====================================================================
 *
 * ldp : regiser 2개에 8byte씩 읽어온다.
 * x12 : x9가 가리키는 값이 저장.
 * x13 : x9 + 8이 가리키는값이 저장.
 * 계산후 x9는 #24만큼 증가.
 *
 *  ----------------------------------
 *  ldp + ldr을 표현하면 아래와 같다.
 *  x12 = [x9];
 *  x13 = [x9, 8];
 *  x9 += 24;
 *  x14 = [x9 - 8];
 *  ----------------------------------
 *
 * 그리고 relative type이 아니면 skip하고. type이 맞다면
 * x14가 가리키는곳에 x12를 저장한다.
 *
 * randomized를 하면 kernel 주소가 조금씩 틀어지는데 
 * 이 경우 x23이 조금바뀐다. 이것에 대한 보정을 해준다.
 *  
 * ---
 *
 */
	ldp	x12, x13, [x9], #24
	ldr	x14, [x9, #-8]
	cmp	w13, #R_AARCH64_RELATIVE
	b.ne	0b
	add	x14, x14, x23			// relocate
	str	x14, [x12, x23]
	b	0b

1:
#ifdef CONFIG_RELR
	/*
	 * Apply RELR relocations.
	 *
	 * RELR is a compressed format for storing relative relocations. The
	 * encoded sequence of entries looks like:
	 * [ AAAAAAAA BBBBBBB1 BBBBBBB1 ... AAAAAAAA BBBBBB1 ... ]
	 *
	 * i.e. start with an address, followed by any number of bitmaps. The
	 * address entry encodes 1 relocation. The subsequent bitmap entries
	 * encode up to 63 relocations each, at subsequent offsets following
	 * the last address entry.
	 *
	 * The bitmap entries must have 1 in the least significant bit. The
	 * assumption here is that an address cannot have 1 in lsb. Odd
	 * addresses are not supported. Any odd addresses are stored in the RELA
	 * section, which is handled above.
	 *
	 * Excluding the least significant bit in the bitmap, each non-zero
	 * bit in the bitmap represents a relocation to be applied to
	 * a corresponding machine word that follows the base address
	 * word. The second least significant bit represents the machine
	 * word immediately following the initial address, and each bit
	 * that follows represents the next word, in linear order. As such,
	 * a single bitmap can encode up to 63 relocations in a 64-bit object.
	 *
	 * In this implementation we store the address of the next RELR table
	 * entry in x9, the address being relocated by the current address or
	 * bitmap entry in x13 and the address being relocated by the current
	 * bit in x14.
	 *
	 * Because addends are stored in place in the binary, RELR relocations
	 * cannot be applied idempotently. We use x24 to keep track of the
	 * currently applied displacement so that we can correctly relocate if
	 * __relocate_kernel is called twice with non-zero displacements (i.e.
	 * if there is both a physical misalignment and a KASLR displacement).
	 */
	ldr	w9, =__relr_offset		// offset to reloc table
	ldr	w10, =__relr_size		// size of reloc table
	add	x9, x9, x11			// __va(.relr)
	add	x10, x9, x10			// __va(.relr) + sizeof(.relr)

	sub	x15, x23, x24			// delta from previous offset
	cbz	x15, 7f				// nothing to do if unchanged
	mov	x24, x23			// save new offset

2:	cmp	x9, x10
	b.hs	7f
	ldr	x11, [x9], #8
	tbnz	x11, #0, 3f			// branch to handle bitmaps
	add	x13, x11, x23
	ldr	x12, [x13]			// relocate address entry
	add	x12, x12, x15
	str	x12, [x13], #8			// adjust to start of bitmap
	b	2b

3:	mov	x14, x13
4:	lsr	x11, x11, #1
	cbz	x11, 6f
	tbz	x11, #0, 5f			// skip bit if not set
	ldr	x12, [x14]			// relocate bit
	add	x12, x12, x15
	str	x12, [x14]

5:	add	x14, x14, #8			// move to next bit's address
	b	4b

6:	/*
	 * Move to the next bitmap's address. 8 is the word size, and 63 is the
	 * number of significant bits in a bitmap entry.
	 */
	add	x13, x13, #(8 * 63)
	b	2b

7:
#endif
	ret

SYM_FUNC_END(__relocate_kernel)
#endif

SYM_FUNC_START_LOCAL(__primary_switch)
/*
 * IAMROOT, 2021.08.28:
 * - CONFIG_RANDOMIZE_BASE : 일단 생략
 * - CONFIG_RELR : 일단 생략
 *
 * x0: __cpu_setup에서 제일 마지막에 SCTRL_EL1_SET 매크로를 이용하여
 *     sctrl_el1에 설정하려는 bits 값이 들어 있음.
 *     x0 값은 sctrl_el1에서 읽은것이 아니라 bitmask를 통해 하드코딩으로
 *     설정된 값.
 */
#ifdef CONFIG_RANDOMIZE_BASE
	mov	x19, x0				// preserve new SCTLR_EL1 value
	mrs	x20, sctlr_el1			// preserve old SCTLR_EL1 value
#endif

	adrp	x1, init_pg_dir
	bl	__enable_mmu
#ifdef CONFIG_RELOCATABLE
#ifdef CONFIG_RELR
	mov	x24, #0				// no RELR displacement yet
#endif
	bl	__relocate_kernel
#ifdef CONFIG_RANDOMIZE_BASE
	ldr	x8, =__primary_switched
	adrp	x0, __PHYS_OFFSET
	blr	x8

	/*
	 * If we return here, we have a KASLR displacement in x23 which we need
	 * to take into account by discarding the current kernel mapping and
	 * creating a new one.
	 */
	pre_disable_mmu_workaround
	msr	sctlr_el1, x20			// disable the MMU
	isb
	bl	__create_page_tables		// recreate kernel mapping

	tlbi	vmalle1				// Remove any stale TLB entries
	dsb	nsh

	msr	sctlr_el1, x19			// re-enable the MMU
	isb
	ic	iallu				// flush instructions fetched
	dsb	nsh				// via old mapping
	isb

	bl	__relocate_kernel
#endif
#endif
	ldr	x8, =__primary_switched
	adrp	x0, __PHYS_OFFSET
	br	x8
SYM_FUNC_END(__primary_switch)
