// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/init.c
 *
 * Copyright (C) 1995-2005 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/efi.h>
#include <linux/swiotlb.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>
#include <linux/hugetlb.h>

#include <asm/boot.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/memory.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/sizes.h>
#include <asm/tlb.h>
#include <asm/alternative.h>

#define ARM64_ZONE_DMA_BITS	30

/*
 * We need to be able to catch inadvertent references to memstart_addr
 * that occur (potentially in generic code) before arm64_memblock_init()
 * executes, which assigns it its actual value. So use a default value
 * that cannot be mistaken for a real physical address.
 */
/*
 * IAMROOT, 2021.10.23:
 * - arm64_memblock_init에서 초기화된다. 이 값이 초기화 되기전엔
 *   리니어 매핑이 완료되지 않은 상태이므로
 *   phys_to_virt등의 변환 매크로를 사용할수 없다.
 *
 *   해당값이 초기화할때 VA_BITS, vabits_actual에 따라서 보정을 해주는데
 *   다음과 같은 예제 사유를 따른다.
 *   
 * ex) VA_BITS = 48, vabits_actual = 48, 
 *     PAGE_SIZE = 4k, memstart = 0x8000_0000
 *
 *	PAGE_OFFSET = 0xffff_0000_0000_0000
 *
 *	phys_addr = 0x9000_0000
 *	
 *	__phys_to_virt(x) = (((x) - PHYS_OFFSET) | PAGE_OFFSET)
 *	__phys_to_virt(0x9000_0000) = 0x9000_0000 - 0x8000_0000 |
 *				      0xffff_0000_0000_0000
 *				    = 0xffff_0000_1000_0000
 *
 * ex) VA_BITS = 52,  vabits_actual = 48,
 *     PAGE_SIZE = 16, memstart = 0x8000_0000 (틀린사례)
 *				    
 *	PAGE_OFFSET = 0xfff0_0000_0000_0000
 *
 *	phys_addr = 0x9000_0000
 *	
 *	__phys_to_virt(x) = (((x) - PHYS_OFFSET) | PAGE_OFFSET)
 *	__phys_to_virt(0x9000_0000) = 0x9000_0000 - 0x8000_0000 |
 *				      0xfff0_0000_0000_0000
 *				    = 0xfff0_0000_1000_0000
 *
 * ex) VA_BITS = 52,  vabits_actual = 48,
 *     PAGE_SIZE = 16, memstart = -0xe_ffff_8000_0000 (memstart가 보정된 사례)
 *				    
 *	PAGE_OFFSET = 0xfff0_0000_0000_0000
 *
 *	phys_addr = 0x9000_0000
 *	
 *	__phys_to_virt(x) = (((x) - PHYS_OFFSET) | PAGE_OFFSET)
 *	__phys_to_virt(0x9000_0000) = 0x9000_0000 - (-0xe_ffff_8000_0000) |
 *				      0xfff0_0000_0000_0000
 *				    = 0xffff_0000_1000_0000
 *
 * 즉 실제 vabits와 compile 타임에 계산된 VA_BITS의 차이를 보정해줘야
 * 제대로된 물리, 가상주소 변환값이 계산된다.
 */
s64 memstart_addr __ro_after_init = -1;
EXPORT_SYMBOL(memstart_addr);

/*
 * We create both ZONE_DMA and ZONE_DMA32. ZONE_DMA covers the first 1G of
 * memory as some devices, namely the Raspberry Pi 4, have peripherals with
 * this limited view of the memory. ZONE_DMA32 will cover the rest of the 32
 * bit addressable memory area.
 */
/*
 * IAMROOT, 2021.10.23:
 * - arm64_memblock_init에서 ARM64_ZONE_DMA_BITS 와 ram 크기를
 *   비교해 작은 값으로 초기화 된다.
 */
phys_addr_t arm64_dma_phys_limit __ro_after_init;
static phys_addr_t arm64_dma32_phys_limit __ro_after_init;

#ifdef CONFIG_KEXEC_CORE
/*
 * reserve_crashkernel() - reserves memory for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by dump capture kernel when
 * primary kernel is crashing.
 */
/*
 * IAMROOT, 2021.10.23:
 * - crash dump 용으로 작은 kernel을 올릴 영역을 reserve 한다.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_base, crash_size;
	int ret;

	ret = parse_crashkernel(boot_command_line, memblock_phys_mem_size(),
				&crash_size, &crash_base);
	/* no crashkernel= or invalid value specified */
	if (ret || !crash_size)
		return;

	crash_size = PAGE_ALIGN(crash_size);

	if (crash_base == 0) {
		/* Current arm64 boot protocol requires 2MB alignment */
		crash_base = memblock_find_in_range(0, arm64_dma32_phys_limit,
				crash_size, SZ_2M);
		if (crash_base == 0) {
			pr_warn("cannot allocate crashkernel (size:0x%llx)\n",
				crash_size);
			return;
		}
	} else {
		/* User specifies base address explicitly. */
		if (!memblock_is_region_memory(crash_base, crash_size)) {
			pr_warn("cannot reserve crashkernel: region is not memory\n");
			return;
		}

		if (memblock_is_region_reserved(crash_base, crash_size)) {
			pr_warn("cannot reserve crashkernel: region overlaps reserved memory\n");
			return;
		}

		if (!IS_ALIGNED(crash_base, SZ_2M)) {
			pr_warn("cannot reserve crashkernel: base address is not 2MB aligned\n");
			return;
		}
	}
	memblock_reserve(crash_base, crash_size);

	pr_info("crashkernel reserved: 0x%016llx - 0x%016llx (%lld MB)\n",
		crash_base, crash_base + crash_size, crash_size >> 20);

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
}
#else
static void __init reserve_crashkernel(void)
{
}
#endif /* CONFIG_KEXEC_CORE */

#ifdef CONFIG_CRASH_DUMP
static int __init early_init_dt_scan_elfcorehdr(unsigned long node,
		const char *uname, int depth, void *data)
{
	const __be32 *reg;
	int len;

	if (depth != 1 || strcmp(uname, "chosen") != 0)
		return 0;

	reg = of_get_flat_dt_prop(node, "linux,elfcorehdr", &len);
	if (!reg || (len < (dt_root_addr_cells + dt_root_size_cells)))
		return 1;

	elfcorehdr_addr = dt_mem_next_cell(dt_root_addr_cells, &reg);
	elfcorehdr_size = dt_mem_next_cell(dt_root_size_cells, &reg);

	return 1;
}

/*
 * reserve_elfcorehdr() - reserves memory for elf core header
 *
 * This function reserves the memory occupied by an elf core header
 * described in the device tree. This region contains all the
 * information about primary kernel's core image and is used by a dump
 * capture kernel to access the system memory on primary kernel.
 */
static void __init reserve_elfcorehdr(void)
{
	of_scan_flat_dt(early_init_dt_scan_elfcorehdr, NULL);

	if (!elfcorehdr_size)
		return;

	if (memblock_is_region_reserved(elfcorehdr_addr, elfcorehdr_size)) {
		pr_warn("elfcorehdr is overlapped\n");
		return;
	}

	memblock_reserve(elfcorehdr_addr, elfcorehdr_size);

	pr_info("Reserving %lldKB of memory at 0x%llx for elfcorehdr\n",
		elfcorehdr_size >> 10, elfcorehdr_addr);
}
#else
static void __init reserve_elfcorehdr(void)
{
}
#endif /* CONFIG_CRASH_DUMP */

/*
 * Return the maximum physical address for a zone with a given address size
 * limit. It currently assumes that for memory starting above 4G, 32-bit
 * devices will use a DMA offset.
 */
/*
 * IAMROOT, 2021.10.23:
 * - ram 크기 or zone_bits 이내로 범위를 조정한다.
 */
static phys_addr_t __init max_zone_phys(unsigned int zone_bits)
{
	phys_addr_t offset = memblock_start_of_DRAM() & GENMASK_ULL(63, zone_bits);
	return min(offset + (1ULL << zone_bits), memblock_end_of_DRAM());
}

static void __init zone_sizes_init(unsigned long min, unsigned long max)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES]  = {0};

#ifdef CONFIG_ZONE_DMA
	max_zone_pfns[ZONE_DMA] = PFN_DOWN(arm64_dma_phys_limit);
#endif
#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(arm64_dma32_phys_limit);
#endif
	max_zone_pfns[ZONE_NORMAL] = max;

	free_area_init(max_zone_pfns);
}

int pfn_valid(unsigned long pfn)
{
	phys_addr_t addr = pfn << PAGE_SHIFT;

	if ((addr >> PAGE_SHIFT) != pfn)
		return 0;

#ifdef CONFIG_SPARSEMEM
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;

	if (!valid_section(__pfn_to_section(pfn)))
		return 0;
#endif
	return memblock_is_map_memory(addr);
}
EXPORT_SYMBOL(pfn_valid);

/*
 * IAMROOT, 2021.10.23:
 * - command line이나 dt에서 해당값을 초기화 할수 있다.
 */
static phys_addr_t memory_limit = PHYS_ADDR_MAX;

/*
 * Limit the memory size that was specified via FDT.
 */
static int __init early_mem(char *p)
{
	if (!p)
		return 1;

	memory_limit = memparse(p, &p) & PAGE_MASK;
	pr_notice("Memory limited to %lldMB\n", memory_limit >> 20);

	return 0;
}
early_param("mem", early_mem);

static int __init early_init_dt_scan_usablemem(unsigned long node,
		const char *uname, int depth, void *data)
{
	struct memblock_region *usablemem = data;
	const __be32 *reg;
	int len;

	if (depth != 1 || strcmp(uname, "chosen") != 0)
		return 0;

	reg = of_get_flat_dt_prop(node, "linux,usable-memory-range", &len);
	if (!reg || (len < (dt_root_addr_cells + dt_root_size_cells)))
		return 1;

	usablemem->base = dt_mem_next_cell(dt_root_addr_cells, &reg);
	usablemem->size = dt_mem_next_cell(dt_root_size_cells, &reg);

	return 1;
}
/*
 * IAMROOT, 2021.10.23:
 * - dt에 chosen node에서 linux,usable-memory-range prop 범위의 값이 존재하면
 *   해당 범위외를 전부 remove 한다.
 *
 * - 예를들어 system이 4기가라고 할때, 1기가일때, 2기가일때등을 한번 테스트
 *   해봐야 되는 상황등에 사용하는 경우가 있따.
 */
static void __init fdt_enforce_memory_region(void)
{
	struct memblock_region reg = {
		.size = 0,
	};

	of_scan_flat_dt(early_init_dt_scan_usablemem, &reg);

	if (reg.size)
		memblock_cap_memory_range(reg.base, reg.size);
}

void __init arm64_memblock_init(void)
{
/*
 * IAMROOT, 2021.10.23:
 * - 절반만 리니어 매핑영역이므로 vabits 에서 -1 한것을 size로함 (128TB)
 */
	const s64 linear_region_size = BIT(vabits_actual - 1);

	/* Handle linux,usable-memory-range property */
	fdt_enforce_memory_region();

/*
 * IAMROOT, 2021.10.23:
 * - 물리주소 범위를 벗어나는 영역을 지운다
 *
 * 표는 적당히 다음과 같은 순서대로 address가 설정되있다고 했을때
 * memblock 상태를 표시한다. (fdt_enforce_memory_region 이후만 고려)
 */
	/* Remove memory above our supported physical address size */
	memblock_remove(1ULL << PHYS_MASK_SHIFT, ULLONG_MAX);

	/*
	 * Select a suitable value for the base of physical memory.
	 */
	memstart_addr = round_down(memblock_start_of_DRAM(),
				   ARM64_MEMSTART_ALIGN);

	/*
	 * Remove the memory that we will not be able to cover with the
	 * linear mapping. Take care not to clip the kernel which may be
	 * high in memory.
	 */
/*
 * IAMROOT, 2021.10.23:
 * - 리니어 매핑 영역보다 큰 물리메모리 영역을 제거한다.
 * 
 * 최초에 dt에서 memstart ~ memblock_end_of_DRAM() 까지 memory add를 한
 * 상태였을것이다.
 *
 * 그런데 만약 memstart_addr + linear_region_size 가 memblock_end_of_DRAM 작다면,
 * 즉 128TB 이상이라면 memblock_addr의 주소를 올려 128 TB의 크기로 맞춰버린다.
 *
 * 그렇게되면 old_memblock_addr ~ memblock_addr 부분이 아직 memblock add 로
 * 남았을것이므로 그 부분을 지우기 위해 0 ~ memblock_addr까지 지운다.
 *
 * memstart_addr 수정전)
 * address                  | memblock
 * -------------------------+--------
 * ..                       | remove
 * memblock_end_of_DRAM()   | remove
 * ..                       | add
 * (linear_region_size      | add
 * 보다 큰 간격)            | add
 * ...                      | add
 * memstart_addr            | add
 * ...                      | remove
 * -------------------------+--------
 *
 * memstart_addr 수정후)
 * address                  | memblock
 * -------------------------+--------
 * ..                       | remove
 * memblock_end_of_DRAM()   | remove
 * ..                       | add
 * linear_region_size       | add
 * ...                      | add
 * memstart_addr      <.    | add 
 * ...                 |    | add <-- memstart_addr이 위로 올라갔으므로
 * (old_memstart_addr) /    | add <-- 이 부분들이 remove되야된다.
 * ...                      | remove
 * -------------------------+--------
 *
 * memblock_remove(0, memstart_addr) 후)
 *
 * address                  | memblock
 * -------------------------+--------
 * ..                       | remove
 * memblock_end_of_DRAM()   | remove
 * ..                       | add
 * linear_region_size       | add
 * ...                      | add
 * memstart_addr            | add 
 * ...                      | *remove
 * old_memstart_addr        | *remove
 * ...                      | remove
 * -------------------------+--------
 */
	memblock_remove(max_t(u64, memstart_addr + linear_region_size,
			__pa_symbol(_end)), ULLONG_MAX);
	if (memstart_addr + linear_region_size < memblock_end_of_DRAM()) {
		/* ensure that memstart_addr remains sufficiently aligned */
		memstart_addr = round_up(memblock_end_of_DRAM() - linear_region_size,
					 ARM64_MEMSTART_ALIGN);
		memblock_remove(0, memstart_addr);
	}

	/*
	 * If we are running with a 52-bit kernel VA config on a system that
	 * does not support it, we have to place the available physical
	 * memory in the 48-bit addressable part of the linear region, i.e.,
	 * we have to move it upward. Since memstart_addr represents the
	 * physical address of PAGE_OFFSET, we have to *subtract* from it.
	 */
/*
 * IAMROOT, 2021.10.23:
 * memstart_addr의 주석에 있는 내용과 같은 상황(config의 VA_BITS와
 * vabits_actual이 다른 상황)에서 와 같이 그냥 memstart_addr을 사용하면
 * 오차가 발생해버린다. 이 오차를 이 시점에서 보정을 해준다.
 *
 * memstart_addr = 0x8000_0000
 * _PAGE_OFFSET(48) = 0xffff_0000_0000_0000
 * _PAGE_OFFSET(52) = 0xfff0_0000_0000_0000
 *
 * memstart_addr = 0x8000_0000 - 0xf_0000_0000_0000
 *               = -0xe_ffff_8000_0000
 *
 * 해당 주석의 마지막 예제로가면 보정된 결과가 있다.
 */
	if (IS_ENABLED(CONFIG_ARM64_VA_BITS_52) && (vabits_actual != 52))
		memstart_addr -= _PAGE_OFFSET(48) - _PAGE_OFFSET(52);

	/*
	 * Apply the memory limit if it was set. Since the kernel may be loaded
	 * high up in memory, add back the kernel region that must be accessible
	 * via the linear mapping.
	 */
/*
 * IAMROOT, 2021.10.23:
 * - 외부에서 memory_limis값이 지정이되면 해당값을 기준으로 초기화가 이루어진다.
 *   memory_limit ~ PHYS_ADDR_MAX를 전부 remove 한다.
 *
 * - kernel이 dram의 위쪽에 load가 될수있는데 이 때 kernel 영역이
 *   memory_limit 을 걸치고있거나 위에 있을 수 있어 kernel image 영역이
 *   제거될수있으므로 다시 add를 해준다.
 */
	if (memory_limit != PHYS_ADDR_MAX) {
		memblock_mem_limit_remove_map(memory_limit);
		memblock_add(__pa_symbol(_text), (u64)(_end - _text));
	}
/*
 * IAMROOT, 2021.10.23:
 * - initrd 영역을 reserved한다.
 */
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/*
		 * Add back the memory we just removed if it results in the
		 * initrd to become inaccessible via the linear mapping.
		 * Otherwise, this is a no-op
		 */
		u64 base = phys_initrd_start & PAGE_MASK;
		u64 size = PAGE_ALIGN(phys_initrd_start + phys_initrd_size) - base;

		/*
		 * We can only add back the initrd memory if we don't end up
		 * with more memory than we can address via the linear mapping.
		 * It is up to the bootloader to position the kernel and the
		 * initrd reasonably close to each other (i.e., within 32 GB of
		 * each other) so that all granule/#levels combinations can
		 * always access both.
		 */
		if (WARN(base < memblock_start_of_DRAM() ||
			 base + size > memblock_start_of_DRAM() +
				       linear_region_size,
			"initrd not fully accessible via the linear mapping -- please check your bootloader ...\n")) {
			phys_initrd_size = 0;
		} else {
/*
 * IAMROOT, 2021.10.23:
 * - 해당영역이 flag가 존재할수있으므로 그냥 remove를 한다.
 */
			memblock_remove(base, size); /* clear MEMBLOCK_ flags */
			memblock_add(base, size);
			memblock_reserve(base, size);
		}
	}
/*
 * IAMROOT, 2021.10.23:
 * - CONFIG_RANDOMIZE_BASE가 적용되있으면 다시한번 memstart_addr를 고쳐준다.
 */
	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern u16 memstart_offset_seed;
		u64 range = linear_region_size -
			    (memblock_end_of_DRAM() - memblock_start_of_DRAM());

		/*
		 * If the size of the linear region exceeds, by a sufficient
		 * margin, the size of the region that the available physical
		 * memory spans, randomize the linear region as well.
		 */
		if (memstart_offset_seed > 0 && range >= ARM64_MEMSTART_ALIGN) {
			range /= ARM64_MEMSTART_ALIGN;
/*
 * IAMROOT, 2021.10.27:
 * - memstart_offset_seed는 seed 상위 16bit를 사용했었다.
 *   즉 memstart_offset_seed는 16bit 이하의 값인데 여기에 range를 곱해서
 *   memstart_offset_seed의 범위인 16 bit를 넘는 값만을 사용해서 마진을 구할려고
 *   다음과 같은 식들을 사용한거 같다.
 */
			memstart_addr -= ARM64_MEMSTART_ALIGN *
					 ((range * memstart_offset_seed) >> 16);
		}
	}

	/*
	 * Register the kernel text, kernel data, initrd, and initial
	 * pagetables with memblock.
	 */
/*
 * IAMROOT, 2021.10.23:
 * - kernel 영역을 reserve
 */
	memblock_reserve(__pa_symbol(_text), _end - _text);

	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/* the generic initrd code expects virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}
/*
 * IAMROOT, 2021.10.23:
 * - dt에서 지정한 reserved 영역 등록
 */
	early_init_fdt_scan_reserved_mem();

	if (IS_ENABLED(CONFIG_ZONE_DMA)) {
		zone_dma_bits = ARM64_ZONE_DMA_BITS;
		arm64_dma_phys_limit = max_zone_phys(ARM64_ZONE_DMA_BITS);
	}

	if (IS_ENABLED(CONFIG_ZONE_DMA32))
		arm64_dma32_phys_limit = max_zone_phys(32);
	else
		arm64_dma32_phys_limit = PHYS_MASK + 1;

	reserve_crashkernel();

	reserve_elfcorehdr();

/*
 * IAMROOT, 2021.10.23:
 * - va를 사용시 범위를 벗어나면 안되서 -1을 해줬다가 결과 가상주소에 + 1을 한다.
 */
	high_memory = __va(memblock_end_of_DRAM() - 1) + 1;

	dma_contiguous_reserve(arm64_dma32_phys_limit);
}
/*
 * IAMROOT, 2021.11.06:
 * - ex) 0x8000_0000 ~ 0xffff_ffff(2GB)
 *   memblock_start_of_DRAM = 0x8000_0000
 *   memblock_end_of_DRAM = 0x1_0000_0000
 *   min =  0x8_0000
 *   max = 0x10_0000
 */
void __init bootmem_init(void)
{
	unsigned long min, max;

	min = PFN_UP(memblock_start_of_DRAM());
	max = PFN_DOWN(memblock_end_of_DRAM());

	early_memtest(min << PAGE_SHIFT, max << PAGE_SHIFT);

	max_pfn = max_low_pfn = max;
	min_low_pfn = min;

	arm64_numa_init();

	/*
	 * must be done after arm64_numa_init() which calls numa_init() to
	 * initialize node_online_map that gets used in hugetlb_cma_reserve()
	 * while allocating required CMA size across online nodes.
	 */
#if defined(CONFIG_HUGETLB_PAGE) && defined(CONFIG_CMA)
	arm64_hugetlb_cma_reserve();
#endif

	dma_pernuma_cma_reserve();

	/*
	 * sparse_init() tries to allocate memory from memblock, so must be
	 * done after the fixed reservations
	 */
	sparse_init();
	zone_sizes_init(min, max);

	memblock_dump_all();
}

#ifndef CONFIG_SPARSEMEM_VMEMMAP
static inline void free_memmap(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *start_pg, *end_pg;
	unsigned long pg, pgend;

	/*
	 * Convert start_pfn/end_pfn to a struct page pointer.
	 */
	start_pg = pfn_to_page(start_pfn - 1) + 1;
	end_pg = pfn_to_page(end_pfn - 1) + 1;

	/*
	 * Convert to physical addresses, and round start upwards and end
	 * downwards.
	 */
	pg = (unsigned long)PAGE_ALIGN(__pa(start_pg));
	pgend = (unsigned long)__pa(end_pg) & PAGE_MASK;

	/*
	 * If there are free pages between these, free the section of the
	 * memmap array.
	 */
	if (pg < pgend)
		memblock_free(pg, pgend - pg);
}

/*
 * The mem_map array can get very big. Free the unused area of the memory map.
 */
static void __init free_unused_memmap(void)
{
	unsigned long start, end, prev_end = 0;
	int i;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start, &end, NULL) {
#ifdef CONFIG_SPARSEMEM
		/*
		 * Take care not to free memmap entries that don't exist due
		 * to SPARSEMEM sections which aren't present.
		 */
		start = min(start, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
		/*
		 * If we had a previous bank, and there is a space between the
		 * current bank and the previous, free it.
		 */
		if (prev_end && prev_end < start)
			free_memmap(prev_end, start);

		/*
		 * Align up here since the VM subsystem insists that the
		 * memmap entries are valid from the bank end aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		prev_end = ALIGN(end, MAX_ORDER_NR_PAGES);
	}

#ifdef CONFIG_SPARSEMEM
	if (!IS_ALIGNED(prev_end, PAGES_PER_SECTION))
		free_memmap(prev_end, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
}
#endif	/* !CONFIG_SPARSEMEM_VMEMMAP */

/*
 * mem_init() marks the free areas in the mem_map and tells us how much memory
 * is free.  This is done after various parts of the system have claimed their
 * memory after the kernel image.
 */
void __init mem_init(void)
{
	if (swiotlb_force == SWIOTLB_FORCE ||
	    max_pfn > PFN_DOWN(arm64_dma_phys_limit ? : arm64_dma32_phys_limit))
		swiotlb_init(1);
	else
		swiotlb_force = SWIOTLB_NO_FORCE;

	set_max_mapnr(max_pfn - PHYS_PFN_OFFSET);

#ifndef CONFIG_SPARSEMEM_VMEMMAP
	free_unused_memmap();
#endif
	/* this will put all unused low memory onto the freelists */
	memblock_free_all();

	mem_init_print_info(NULL);

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can be
	 * detected at build time already.
	 */
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(TASK_SIZE_32 > DEFAULT_MAP_WINDOW_64);
#endif

	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get anywhere without
		 * overcommit, so turn it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
	free_reserved_area(lm_alias(__init_begin),
			   lm_alias(__init_end),
			   POISON_FREE_INITMEM, "unused kernel");
	/*
	 * Unmap the __init region but leave the VM area in place. This
	 * prevents the region from being reused for kernel modules, which
	 * is not supported by kallsyms.
	 */
	unmap_kernel_range((u64)__init_begin, (u64)(__init_end - __init_begin));
}

void dump_mem_limit(void)
{
	if (memory_limit != PHYS_ADDR_MAX) {
		pr_emerg("Memory Limit: %llu MB\n", memory_limit >> 20);
	} else {
		pr_emerg("Memory Limit: none\n");
	}
}
