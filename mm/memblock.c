// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp.	June 2001.
 * Copyright (C) 2001 Peter Bergner.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/poison.h>
#include <linux/pfn.h>
#include <linux/debugfs.h>
#include <linux/kmemleak.h>
#include <linux/seq_file.h>
#include <linux/memblock.h>

#include <asm/sections.h>
#include <linux/io.h>

#include "internal.h"

#define INIT_MEMBLOCK_REGIONS			128
#define INIT_PHYSMEM_REGIONS			4

#ifndef INIT_MEMBLOCK_RESERVED_REGIONS
# define INIT_MEMBLOCK_RESERVED_REGIONS		INIT_MEMBLOCK_REGIONS
#endif

/**
 * DOC: memblock overview
 *
 * Memblock is a method of managing memory regions during the early
 * boot period when the usual kernel memory allocators are not up and
 * running.
 *
 * Memblock views the system memory as collections of contiguous
 * regions. There are several types of these collections:
 *
 * * ``memory`` - describes the physical memory available to the
 *   kernel; this may differ from the actual physical memory installed
 *   in the system, for instance when the memory is restricted with
 *   ``mem=`` command line parameter
 * * ``reserved`` - describes the regions that were allocated
 * * ``physmem`` - describes the actual physical memory available during
 *   boot regardless of the possible restrictions and memory hot(un)plug;
 *   the ``physmem`` type is only available on some architectures.
 *
 * Each region is represented by struct memblock_region that
 * defines the region extents, its attributes and NUMA node id on NUMA
 * systems. Every memory type is described by the struct memblock_type
 * which contains an array of memory regions along with
 * the allocator metadata. The "memory" and "reserved" types are nicely
 * wrapped with struct memblock. This structure is statically
 * initialized at build time. The region arrays are initially sized to
 * %INIT_MEMBLOCK_REGIONS for "memory" and %INIT_MEMBLOCK_RESERVED_REGIONS
 * for "reserved". The region array for "physmem" is initially sized to
 * %INIT_PHYSMEM_REGIONS.
 * The memblock_allow_resize() enables automatic resizing of the region
 * arrays during addition of new regions. This feature should be used
 * with care so that memory allocated for the region array will not
 * overlap with areas that should be reserved, for example initrd.
 *
 * The early architecture setup should tell memblock what the physical
 * memory layout is by using memblock_add() or memblock_add_node()
 * functions. The first function does not assign the region to a NUMA
 * node and it is appropriate for UMA systems. Yet, it is possible to
 * use it on NUMA systems as well and assign the region to a NUMA node
 * later in the setup process using memblock_set_node(). The
 * memblock_add_node() performs such an assignment directly.
 *
 * Once memblock is setup the memory can be allocated using one of the
 * API variants:
 *
 * * memblock_phys_alloc*() - these functions return the **physical**
 *   address of the allocated memory
 * * memblock_alloc*() - these functions return the **virtual** address
 *   of the allocated memory.
 *
 * Note, that both API variants use implicit assumptions about allowed
 * memory ranges and the fallback methods. Consult the documentation
 * of memblock_alloc_internal() and memblock_alloc_range_nid()
 * functions for more elaborate description.
 *
 * As the system boot progresses, the architecture specific mem_init()
 * function frees all the memory to the buddy page allocator.
 *
 * Unless an architecture enables %CONFIG_ARCH_KEEP_MEMBLOCK, the
 * memblock data structures (except "physmem") will be discarded after the
 * system initialization completes.
 */

#ifndef CONFIG_NEED_MULTIPLE_NODES
struct pglist_data __refdata contig_page_data;
EXPORT_SYMBOL(contig_page_data);
#endif

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;
unsigned long long max_possible_pfn;

static struct memblock_region memblock_memory_init_regions[INIT_MEMBLOCK_REGIONS] __initdata_memblock;
static struct memblock_region memblock_reserved_init_regions[INIT_MEMBLOCK_RESERVED_REGIONS] __initdata_memblock;
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
static struct memblock_region memblock_physmem_init_regions[INIT_PHYSMEM_REGIONS];
#endif
/*
 * IAMROOT, 2021.10.16:
 * - .meminit.data section에 위치한다.
 *
 * - cnt가 1인데, 없을때도 1이고 1개일때도 1이다. 0을 사용하면 안됨.
 */
struct memblock memblock __initdata_memblock = {
	.memory.regions		= memblock_memory_init_regions,
	.memory.cnt		= 1,	/* empty dummy entry */
	.memory.max		= INIT_MEMBLOCK_REGIONS,
	.memory.name		= "memory",

	.reserved.regions	= memblock_reserved_init_regions,
	.reserved.cnt		= 1,	/* empty dummy entry */
	.reserved.max		= INIT_MEMBLOCK_RESERVED_REGIONS,
	.reserved.name		= "reserved",

	.bottom_up		= false,
	.current_limit		= MEMBLOCK_ALLOC_ANYWHERE,
};

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
struct memblock_type physmem = {
	.regions		= memblock_physmem_init_regions,
	.cnt			= 1,	/* empty dummy entry */
	.max			= INIT_PHYSMEM_REGIONS,
	.name			= "physmem",
};
#endif

/*
 * keep a pointer to &memblock.memory in the text section to use it in
 * __next_mem_range() and its helpers.
 *  For architectures that do not keep memblock data after init, this
 * pointer will be reset to NULL at memblock_discard()
 */
static __refdata struct memblock_type *memblock_memory = &memblock.memory;
/*
 * IAMROOT, 2021.10.16:
 * - memblock_type->cnt는 무조건 1이상이기 때문에 최소한 for문은 한번은 진입할것이다.
 *   memblock_type->region[0]부터 끝까지 iteration을 수행한다.
 */
#define for_each_memblock_type(i, memblock_type, rgn)			\
	for (i = 0, rgn = &memblock_type->regions[0];			\
	     i < memblock_type->cnt;					\
	     i++, rgn = &memblock_type->regions[i])

#define memblock_dbg(fmt, ...)						\
	do {								\
		if (memblock_debug)					\
			pr_info(fmt, ##__VA_ARGS__);			\
	} while (0)

static int memblock_debug __initdata_memblock;
/*
 * IAMROOT, 2021.10.23:
 * - disk의 raid랑 비슷한 개념으로 똑같은 값을 미러로 사용하는지의 여부
 *   mirror system을 쓸경우 필요한 데이터보다 2배가 필요한 개념.
 *   운영하다가 error가 발생하면 error message를 발생한다.
 *   kernel만 mirror를 쓰고 application은 mirror를 안쓸수있다.
 *   이 경우 kernel에서도 일부 메모리만 mirror를 쓸수있는데 어떤 memory를
 *   mirror를 쓸지 mark를 해줘야 된다.
 *
 * - arm64에서는 아직까진 사용하지 않아 보인다.
 */
static bool system_has_some_mirror __initdata_memblock = false;
/*
 * IAMROOT, 2021.10.23:
 * - paging init때 memblock alloc이 사용이 가능해지면 1이 된다.
 */
static int memblock_can_resize __initdata_memblock;
static int memblock_memory_in_slab __initdata_memblock = 0;
static int memblock_reserved_in_slab __initdata_memblock = 0;

static enum memblock_flags __init_memblock choose_memblock_flags(void)
{
	return system_has_some_mirror ? MEMBLOCK_MIRROR : MEMBLOCK_NONE;
}

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t memblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
	return *size = min(*size, PHYS_ADDR_MAX - base);
}

/*
 * Address comparison utilities
 */
static unsigned long __init_memblock memblock_addrs_overlap(phys_addr_t base1, phys_addr_t size1,
				       phys_addr_t base2, phys_addr_t size2)
{
	return ((base1 < (base2 + size2)) && (base2 < (base1 + size1)));
}

bool __init_memblock memblock_overlaps_region(struct memblock_type *type,
					phys_addr_t base, phys_addr_t size)
{
	unsigned long i;

	for (i = 0; i < type->cnt; i++)
		if (memblock_addrs_overlap(base, size, type->regions[i].base,
					   type->regions[i].size))
			break;
	return i < type->cnt;
}

/**
 * __memblock_find_range_bottom_up - find free area utility in bottom-up
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Utility called from memblock_find_in_range_node(), find free area bottom-up.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - arm64에서는 미사용
 */
static phys_addr_t __init_memblock
__memblock_find_range_bottom_up(phys_addr_t start, phys_addr_t end,
				phys_addr_t size, phys_addr_t align, int nid,
				enum memblock_flags flags)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	for_each_free_mem_range(i, nid, flags, &this_start, &this_end, NULL) {
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);

		cand = round_up(this_start, align);
		if (cand < this_end && this_end - cand >= size)
			return cand;
	}

	return 0;
}

/**
 * __memblock_find_range_top_down - find free area utility, in top-down
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Utility called from memblock_find_in_range_node(), find free area top-down.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - start 에서 end까지의 free영역을 찾아서 성공하면 start 주소를 return.
 */
static phys_addr_t __init_memblock
__memblock_find_range_top_down(phys_addr_t start, phys_addr_t end,
			       phys_addr_t size, phys_addr_t align, int nid,
			       enum memblock_flags flags)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	for_each_free_mem_range_reverse(i, nid, flags, &this_start, &this_end,
					NULL) {
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);

/*
 * IAMROOT, 2021.10.23:
 * - 찾은 free 영역의 끝주소가 size보다 작으면 당연히 size보다 덜
 * 할당된거니 skip
 */
		if (this_end < size)
			continue;

		cand = round_down(this_end - size, align);
		if (cand >= this_start)
			return cand;
	}

	return 0;
}

/**
 * memblock_find_in_range_node - find free area in given range and node
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Find @size free area aligned to @align in the specified range and node.
 *
 * When allocation direction is bottom-up, the @start should be greater
 * than the end of the kernel image. Otherwise, it will be trimmed. The
 * reason is that we want the bottom-up allocation just near the kernel
 * image so it is highly likely that the allocated memory and the kernel
 * will reside in the same node.
 *
 * If bottom-up allocation failed, will try to allocate memory top-down.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
static phys_addr_t __init_memblock memblock_find_in_range_node(phys_addr_t size,
					phys_addr_t align, phys_addr_t start,
					phys_addr_t end, int nid,
					enum memblock_flags flags)
{
	phys_addr_t kernel_end, ret;

	/* pump up @end */
	if (end == MEMBLOCK_ALLOC_ACCESSIBLE ||
	    end == MEMBLOCK_ALLOC_KASAN)
		end = memblock.current_limit;

	/* avoid allocating the first page */
	start = max_t(phys_addr_t, start, PAGE_SIZE);
	end = max(start, end);
	kernel_end = __pa_symbol(_end);
/*
 * IAMROOT, 2021.10.23:
 * - arm64는 bottom_up이 false로 되있음.
 */
	/*
	 * try bottom-up allocation only when bottom-up mode
	 * is set and @end is above the kernel image.
	 */
	if (memblock_bottom_up() && end > kernel_end) {
		phys_addr_t bottom_up_start;

		/* make sure we will allocate above the kernel */
		bottom_up_start = max(start, kernel_end);

		/* ok, try bottom-up allocation first */
		ret = __memblock_find_range_bottom_up(bottom_up_start, end,
						      size, align, nid, flags);
		if (ret)
			return ret;

		/*
		 * we always limit bottom-up allocation above the kernel,
		 * but top-down allocation doesn't have the limit, so
		 * retrying top-down allocation may succeed when bottom-up
		 * allocation failed.
		 *
		 * bottom-up allocation is expected to be fail very rarely,
		 * so we use WARN_ONCE() here to see the stack trace if
		 * fail happens.
		 */
		WARN_ONCE(IS_ENABLED(CONFIG_MEMORY_HOTREMOVE),
			  "memblock: bottom-up allocation failed, memory hotremove may be affected\n");
	}

	return __memblock_find_range_top_down(start, end, size, align, nid,
					      flags);
}

/**
 * memblock_find_in_range - find free area in given range
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - start부터 end까지의 free 영역을 탐색해서 start address를 구해온다.
 */
phys_addr_t __init_memblock memblock_find_in_range(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align)
{
	phys_addr_t ret;
	enum memblock_flags flags = choose_memblock_flags();

again:
	ret = memblock_find_in_range_node(size, align, start, end,
					    NUMA_NO_NODE, flags);
/*
 * IAMROOT, 2021.10.23:
 * - ret == 0이면 free 영역을 못찾아왔다는것.
 *   mirror flag가 있다면 mirror flag를 지우고 다시한번만 해본다.
 */
	if (!ret && (flags & MEMBLOCK_MIRROR)) {
		pr_warn("Could not allocate %pap bytes of mirrored memory\n",
			&size);
		flags &= ~MEMBLOCK_MIRROR;
		goto again;
	}

	return ret;
}

static void __init_memblock memblock_remove_region(struct memblock_type *type, unsigned long r)
{
/*
 * IAMROOT, 2021.10.23:
 * - r보다 높은 region들을 한칸 땡기는 식으로 r region을 삭제를 진행한다.
 */
	type->total_size -= type->regions[r].size;
	memmove(&type->regions[r], &type->regions[r + 1],
		(type->cnt - (r + 1)) * sizeof(type->regions[r]));
	type->cnt--;

	/* Special case for empty arrays */
	if (type->cnt == 0) {
		WARN_ON(type->total_size != 0);
		type->cnt = 1;
		type->regions[0].base = 0;
		type->regions[0].size = 0;
		type->regions[0].flags = 0;
		memblock_set_region_node(&type->regions[0], MAX_NUMNODES);
	}
}

#ifndef CONFIG_ARCH_KEEP_MEMBLOCK
/**
 * memblock_discard - discard memory and reserved arrays if they were allocated
 */
/*
 * IAMROOT, 2021.10.23:
 * - memory를 buddy system으로 전환할때 관련된 함수.
 */
void __init memblock_discard(void)
{
	phys_addr_t addr, size;

	if (memblock.reserved.regions != memblock_reserved_init_regions) {
		addr = __pa(memblock.reserved.regions);
		size = PAGE_ALIGN(sizeof(struct memblock_region) *
				  memblock.reserved.max);
		__memblock_free_late(addr, size);
	}

	if (memblock.memory.regions != memblock_memory_init_regions) {
		addr = __pa(memblock.memory.regions);
		size = PAGE_ALIGN(sizeof(struct memblock_region) *
				  memblock.memory.max);
		__memblock_free_late(addr, size);
	}

	memblock_memory = NULL;
}
#endif

/**
 * memblock_double_array - double the size of the memblock regions array
 * @type: memblock type of the regions array being doubled
 * @new_area_start: starting address of memory range to avoid overlap with
 * @new_area_size: size of memory range to avoid overlap with
 *
 * Double the size of the @type regions array. If memblock is being used to
 * allocate memory for a new reserved regions array and there is a previously
 * allocated memory range [@new_area_start, @new_area_start + @new_area_size]
 * waiting to be reserved, ensure the memory used by the new array does
 * not overlap.
 *
 * Return:
 * 0 on success, -1 on failure.
 */
static int __init_memblock memblock_double_array(struct memblock_type *type,
						phys_addr_t new_area_start,
						phys_addr_t new_area_size)
{
	struct memblock_region *new_array, *old_array;
	phys_addr_t old_alloc_size, new_alloc_size;
	phys_addr_t old_size, new_size, addr, new_end;
	int use_slab = slab_is_available();
	int *in_slab;

	/* We don't allow resizing until we know about the reserved regions
	 * of memory that aren't suitable for allocation
	 */
/*
 * IAMROOT, 2021.10.23:
 * - paging_init 이 완료되기전에는 동작안한다.
 */
	if (!memblock_can_resize)
		return -1;

	/* Calculate new doubled size */
	old_size = type->max * sizeof(struct memblock_region);
	new_size = old_size << 1;
	/*
	 * We need to allocated new one align to PAGE_SIZE,
	 *   so we can free them completely later.
	 */
	old_alloc_size = PAGE_ALIGN(old_size);
	new_alloc_size = PAGE_ALIGN(new_size);

	/* Retrieve the slab flag */
	if (type == &memblock.memory)
		in_slab = &memblock_memory_in_slab;
	else
		in_slab = &memblock_reserved_in_slab;

/*
 * IAMROOT, 2021.10.23:
 * - memblock은 물리주소(addr)을 할당받아서 가상주소로 변환을 시켜주고,
 *   slab은 가상주소(new_array)를 할당받아서 물리주소(addr)로 변환한다.
 */
	/* Try to find some space for it */
	if (use_slab) {
		new_array = kmalloc(new_size, GFP_KERNEL);
		addr = new_array ? __pa(new_array) : 0;
	} else {
		/* only exclude range when trying to double reserved.regions */
		if (type != &memblock.reserved)
			new_area_start = new_area_size = 0;

		addr = memblock_find_in_range(new_area_start + new_area_size,
						memblock.current_limit,
						new_alloc_size, PAGE_SIZE);
/*
 * IAMROOT, 2021.10.23:
 * 범위 내에서 검색이 실패한경우 마지막부터 바닥까지의 영역으로
 * 검색을 재시도한다.
 */
		if (!addr && new_area_size)
			addr = memblock_find_in_range(0,
				min(new_area_start, memblock.current_limit),
				new_alloc_size, PAGE_SIZE);

		new_array = addr ? __va(addr) : NULL;
	}
/*
 * IAMROOT, 2021.10.30:
 * - 위 if-statement 가 완료된 후에 변수 new_array, addr는 아래와 같은 state를
 *   가진다.
 *
 *   addr = pa(new_array)
 *   new_array = va(addr)
 *
 *   slab을 통한 alloc은 va만 알고 있으므로 addr = pa(new_array)를 해주고,
 *   memblock을 통한 alloc은 pa만 알고 있으므로 new_array = va(addr)를
 *   해줘야한다.
 */

	if (!addr) {
		pr_err("memblock: Failed to double %s array from %ld to %ld entries !\n",
		       type->name, type->max, type->max * 2);
		return -1;
	}

	new_end = addr + new_size - 1;
	memblock_dbg("memblock: %s is doubled to %ld at [%pa-%pa]",
			type->name, type->max * 2, &addr, &new_end);

	/*
	 * Found space, we now need to move the array over before we add the
	 * reserved region since it may be our reserved array itself that is
	 * full.
	 */
/*
 * IAMROOT, 2021.10.23:
 * - 원래 있던 영역크기 만큼(old_size) 복사를하고, 2배확장된만큼 나머지는
 *   0으로 채운다.
 */
	memcpy(new_array, type->regions, old_size);
	memset(new_array + type->max, 0, old_size);
	old_array = type->regions;
	type->regions = new_array;
	type->max <<= 1;

	/* Free old array. We needn't free it if the array is the static one */
/*
 * IAMROOT, 2021.10.23:
 * - slab 할당자가 동작중이면 kfree로 , 아니면 memblock_free로 할당해제한다.
 *
 *   최초엔 static으로 잡혀 있으므로 memblock_free로 지우는개념.
 */
	if (*in_slab)
		kfree(old_array);
	else if (old_array != memblock_memory_init_regions &&
		 old_array != memblock_reserved_init_regions)
		memblock_free(__pa(old_array), old_alloc_size);

	/*
	 * Reserve the new array if that comes from the memblock.  Otherwise, we
	 * needn't do it
	 */
/*
 * IAMROOT, 2021.10.23:
 * - 실제로 reserve로 할당한다.
 */
	if (!use_slab)
		BUG_ON(memblock_reserve(addr, new_alloc_size));

	/* Update slab flag */
	*in_slab = use_slab;

	return 0;
}

/**
 * memblock_merge_regions - merge neighboring compatible regions
 * @type: memblock type to scan
 *
 * Scan @type and merge neighboring compatible regions.
 */
static void __init_memblock memblock_merge_regions(struct memblock_type *type)
{
	int i = 0;
/*
 * IAMROOT, 2021.10.23:
 *                +------+ end
 *                |      |
 *                | next |
 *                |      |
 *  end +------+  +------+ base
 *      |      | 
 *      | this | 
 * base +------+ 
 * 
 * this의 end와 next base가 동일, nid가 같으며 flag가 같으면 두개의 블럭을
 * 합병시킨다.
 *
 *      +--------+ end
 *      |        |
 *      | merged |
 *      | this   |
 *      |        |
 *      |        | 
 *      |        | 
 * base +--------+ 
 */
	/* cnt never goes below 1 */
	while (i < type->cnt - 1) {
		struct memblock_region *this = &type->regions[i];
		struct memblock_region *next = &type->regions[i + 1];

		if (this->base + this->size != next->base ||
		    memblock_get_region_node(this) !=
		    memblock_get_region_node(next) ||
		    this->flags != next->flags) {
			BUG_ON(this->base + this->size > next->base);
			i++;
			continue;
		}

		this->size += next->size;
/*
 * IAMROOT, 2021.10.23:
 * - 합병이 됬으므로 next region에 대한것을 삭제하면서 더 위의 region들을
 *   한칸씩 내림.
 */
		/* move forward from next + 1, index of which is i + 2 */
		memmove(next, next + 1, (type->cnt - (i + 2)) * sizeof(*next));
		type->cnt--;
	}
}

/**
 * memblock_insert_region - insert new memblock region
 * @type:	memblock type to insert into
 * @idx:	index for the insertion point
 * @base:	base address of the new region
 * @size:	size of the new region
 * @nid:	node id of the new region
 * @flags:	flags of the new region
 *
 * Insert new memblock region [@base, @base + @size) into @type at @idx.
 * @type must already have extra room to accommodate the new region.
 */
/*
 * IAMROOT, 2021.10.23:
 * +-----------+
 * | max rgn   |
 * | ...       |
 * | rgn + cnt |
 * | ...       |
 * | rgn + 2   |  
 * | rgn + 1   | 
 * | rgn + 0   | 
 * | ...       |
 * +-----------+
 * - 기존 idx자리에서 cnt까지의 block들을 한칸씩 이동시키고 넣는다.
 */
static void __init_memblock memblock_insert_region(struct memblock_type *type,
						   int idx, phys_addr_t base,
						   phys_addr_t size,
						   int nid,
						   enum memblock_flags flags)
{
	struct memblock_region *rgn = &type->regions[idx];

	BUG_ON(type->cnt >= type->max);
	memmove(rgn + 1, rgn, (type->cnt - idx) * sizeof(*rgn));
	rgn->base = base;
	rgn->size = size;
	rgn->flags = flags;
	memblock_set_region_node(rgn, nid);
	type->cnt++;
	type->total_size += size;
}

/**
 * memblock_add_range - add new memblock region
 * @type: memblock type to add new region into
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 * @flags: flags of the new region
 *
 * Add new memblock region [@base, @base + @size) into @type.  The new region
 * is allowed to overlap with existing ones - overlaps don't affect already
 * existing regions.  @type is guaranteed to be minimal (all neighbouring
 * compatible regions are merged) after the addition.
 *
 * Return:
 * 0 on success, -errno on failure.
 */

/*
 * IAMROOT, 2021.10.16:
 * - @nid: 0, 1, 2, ... 같은 node id가 들어오는데 MAX_NUMNODES를
 *         사용하겟다는것은 어떤 노드든 (any node)상관없다는 의미와 같다.
 *         Non-NUMA 시스템에서 node id는 0으로 처리된다.
 */
static int __init_memblock memblock_add_range(struct memblock_type *type,
				phys_addr_t base, phys_addr_t size,
				int nid, enum memblock_flags flags)
{
	bool insert = false;
	phys_addr_t obase = base;
	phys_addr_t end = base + memblock_cap_size(base, &size);
	int idx, nr_new;
	struct memblock_region *rgn;

	if (!size)
		return 0;
/*
 * IAMROOT, 2021.10.16:
 * - memblock region(memory, reserve)이 비어있는 상태일때.
 *   이 경우 특수케이스로 처리하는데 해당 region에 아무것도
 *   없으므로 단순하게 추가하고 끝낸다.
 *
 * - 오버헤드(cnt 보정, memory 공간 중복시 merge 등) 없이 추가 후
 *   바로 리턴 (fast).
 */
	/* special case for empty array */
	if (type->regions[0].size == 0) {
		WARN_ON(type->cnt != 1 || type->total_size);
		type->regions[0].base = base;
		type->regions[0].size = size;
		type->regions[0].flags = flags;
		memblock_set_region_node(&type->regions[0], nid);
		type->total_size = size;
		return 0;
	}
repeat:
	/*
	 * The following is executed twice.  Once with %false @insert and
	 * then with %true.  The first counts the number of regions needed
	 * to accommodate the new area.  The second actually inserts them.
	 */
	base = obase;
	nr_new = 0;

	for_each_memblock_type(idx, type, rgn) {
		phys_addr_t rbase = rgn->base;
		phys_addr_t rend = rbase + rgn->size;
/*
 * IAMROOT, 2021.10.16:
 * - region base가 요청된 end 보다 크다면 종료
 *
 *  rend +--------+
 *       |        | 
 *       | region | 
 * rbase +--------+ 
 *                  +-----+ end
 *                  |     |
 *                  | new |
 *                  |     |
 *                  +-----+ base
 */
		if (rbase >= end)
			break;
/*
 * IAMROOT, 2021.10.23:
 * - region end가 요청된 base 보다 작다면 다음 region 탐색
 *
 *                  +-----+ end
 *                  |     |
 *                  | new |
 *                  |     |
 *                  +-----+ base
 *  rend +--------+
 *       |        | 
 *       | region | 
 * rbase +--------+ 
 */
		if (rend <= base)
			continue;
		/*
		 * @rgn overlaps.  If it separates the lower part of new
		 * area, insert that portion.
		 */
/*
 * IAMROOT, 2021.10.16:
 * 여기서부터는 기존 region과 새로 추가할 region이 겹치는 경우이며
 * 그에 따른 추가 작업을 수행한다.
 *
 * - region base가 base 보다 크면 rbase - base 영역만 새로 insert.
 *
 * 1) rend >= end 인 상황
 *  rend +--------+
 *       |        | +-----+ end
 *       | region | |     |
 * rbase +--------+ | new |    <--+--------
 *                  |     |       | 추가하는 부분
 *                  +-----+ base  +--------
 */
		if (rbase > base) {
#ifdef CONFIG_NEED_MULTIPLE_NODES
			WARN_ON(nid != memblock_get_region_node(rgn));
#endif
			WARN_ON(flags != rgn->flags);
			nr_new++;
			if (insert)
				memblock_insert_region(type, idx++, base,
						       rbase - base, nid,
						       flags);
		}
/*
 * IAMROOT, 2021.10.16:
 * 
 * rend >= end 라면 추가할 block이 없지만 아래와 같이 rend < end 면
 *
 *                  +-----+ end
 *                  |     |
 *  rend +--------+ |     |
 *       |        | |     | 
 *       | region | |     | 
 * rbase +--------+ | new |
 *                  |     |
 *                  +-----+ base
 *
 * base = min(rend, end)에 의해 다음과 같이 base가 변경된다.
 *
 *                  +-----+ end
 *                  | ins |
 *                  | new |
 *  rend +--------+ +-----+ (after) base
 *       |        | |     | 
 *       | region | |     | 
 * rbase +--------+ |     |
 *                  |     |
 *                  +-----+ (before) base
 *
 * 위와 같은 상황에서 '(after) base ~ end'를 마저 추가해야하므로
 * base는 rend로 설정하고 다음 iterate때 추가한다.
 */
		/* area below @rend is dealt with, forget about it */
		base = min(rend, end);
	}
/*
 * IAMROOT, 2021.10.23:
 * - for문 종료후 'base < end' 조건이 참이라면 추가할 block이 있는 것이므로
 *   해당 block 추가.
 */
	/* insert the remaining portion */
	if (base < end) {
		nr_new++;
		if (insert)
			memblock_insert_region(type, idx, base, end - base,
					       nid, flags);
	}
/*
 * IAMROOT, 2021.10.23:
 * - insert할게 없으면 그냥 종료
 */
	if (!nr_new)
		return 0;

	/*
	 * If this was the first round, resize array and repeat for actual
	 * insertions; otherwise, merge and return.
	 */
	if (!insert) {
/*
 * IAMROOT, 2021.10.23:
 * - 1st loop에서는 memblock region에 추가할 영역의 '갯수(nr_new)'를 계산하고
 *   만약 '갯수 > max(128)' 라면 memblock region을 현재 크기에서 2배수로
 *   확장시킨다.
 *
 * - 계산이 완료되면 'insert = true' flag를 설정하고 'goto repeat' 통해
 *   2th loop를 수행하며 이때 요청 region을 추가한다.
 */
		while (type->cnt + nr_new > type->max)
			if (memblock_double_array(type, obase, size) < 0)
				return -ENOMEM;
		insert = true;
		goto repeat;
	} else {
/*
 * IAMROOT, 2021.10.25:
 * - memblock region 전체를 iter하여 blocks 중에 인접 blocks을 merging
 *   할 수 있다면 merging하여 1개의 block unit으로 만든다.
 */
		memblock_merge_regions(type);
		return 0;
	}
}

/**
 * memblock_add_node - add new memblock region within a NUMA node
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add_node(phys_addr_t base, phys_addr_t size,
				       int nid)
{
	return memblock_add_range(&memblock.memory, base, size, nid, 0);
}

/**
 * memblock_add - add new memblock region
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
/*
 * IAMROOT, 2021.10.16:
 * - memory의 물리시작주소와 size를 memblock.memory에 추가한다.
 */
int __init_memblock memblock_add(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_add_range(&memblock.memory, base, size, MAX_NUMNODES, 0);
}

/**
 * memblock_isolate_range - isolate given range into disjoint memblocks
 * @type: memblock type to isolate range for
 * @base: base of range to isolate
 * @size: size of range to isolate
 * @start_rgn: out parameter for the start of isolated region
 * @end_rgn: out parameter for the end of isolated region
 *
 * Walk @type and ensure that regions don't cross the boundaries defined by
 * [@base, @base + @size).  Crossing regions are split at the boundaries,
 * which may create at most two more regions.  The index of the first
 * region inside the range is returned in *@start_rgn and end in *@end_rgn.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
static int __init_memblock memblock_isolate_range(struct memblock_type *type,
					phys_addr_t base, phys_addr_t size,
					int *start_rgn, int *end_rgn)
{
	phys_addr_t end = base + memblock_cap_size(base, &size);
	int idx;
	struct memblock_region *rgn;

	*start_rgn = *end_rgn = 0;

	if (!size)
		return 0;
/*
 * IAMROOT, 2021.10.23:
 * - 영역을 지울때도 파편화의 가능성이 있으므로 늘어날 경우가 생길수있다.
 */
	/* we'll create at most two more regions */
	while (type->cnt + 2 > type->max)
		if (memblock_double_array(type, base, size) < 0)
			return -ENOMEM;

	for_each_memblock_type(idx, type, rgn) {
		phys_addr_t rbase = rgn->base;
		phys_addr_t rend = rbase + rgn->size;
/*
 * IAMROOT, 2021.10.23:
 * - region base가 요청된 end 보다 크다면 영역을 나눌게 없으므로 종료
 *
 *  rend +--------+
 *       |        | 
 *       | region | 
 *       |        | 
 * rbase +--------+ 
 *                  +------+ end
 *                  |      |
 *                  | isol |
 *                  |      |
 *                  +------+ base
 */
		if (rbase >= end)
			break;
/*
 * IAMROOT, 2021.10.23:
 * - region end가 요청된 base 보다 작다면 다음 region 탐색
 *
 *                  +------+ end
 *                  |      |
 *                  | isol |
 *                  |      |
 *                  +------+ base
 *  rend +--------+
 *       |        | 
 *       | region | 
 * rbase +--------+ 
 */
		if (rend <= base)
			continue;

/*
 * IAMROOT, 2021.10.16:
 * - region base가 base 보다 크다면 그 차이 만큼만 현재 region에 insert 한다
 *
 * 1) rend < end 인 상황
 *  rend +--------+
 *       |        |
 *       |        | +------+ end
 *       |        | |      |
 *       |        | | isol |
 *       |        | |      |
 *       |        | +------+ base
 *       | region | 
 * rbase +--------+ 
 *
 * 다음과 같이 rgn 값들이 설정될것이다.
 *
 *  rend +--------+
 *       |        |
 *       |        | +------+ end
 *       |        | |      |
 *       |        | | isol |
 *       | region | |      |
 *       +--------+ +------+ base
 *       | insert |
 * rbase +--------+ 
 */
		if (rbase < base) {
			/*
			 * @rgn intersects from below.  Split and continue
			 * to process the next region - the new top half.
			 */
			rgn->base = base;
			rgn->size -= base - rbase;
			type->total_size -= base - rbase;
			memblock_insert_region(type, idx, rbase, base - rbase,
					       memblock_get_region_node(rgn),
					       rgn->flags);
/*
 * IAMROOT, 2021.10.23:
 * 2) rend > end 인 상황
 * 
 *  rend +--------+
 *       |        |
 *       |        | +------+ end
 *       |        | |      |
 *       |        | | isol |
 *       | region | |      |
 * rbase +--------+ +------+ base
 *
 * 다음과 같이 된다.
 *
 *  rend +--------+
 *       | region |
 *       +--------+ +------+ end
 *       |        | |      |
 *       |        | | isol |
 *       | insert | |      |
 * rbase +--------+ +------+ base
 */
		} else if (rend > end) {
			/*
			 * @rgn intersects from above.  Split and redo the
			 * current region - the new bottom half.
			 */
			rgn->base = end;
			rgn->size -= end - rbase;
			type->total_size -= end - rbase;
			memblock_insert_region(type, idx--, rbase, end - rbase,
					       memblock_get_region_node(rgn),
					       rgn->flags);
/*
 * IAMROOT, 2021.10.23:
 *                  +------+ end
 * rend  +--------+ |      |
 *       |        | |      |
 *       |        | | isol |
 *       | region | |      |
 * rbase +--------+ |      |
 *                  +------+ base
 *
 * 최초에 한번만 start_rgn이 set되고 end_rgn은 매번 갱신된다.
 * isolate 영역이 경우에따라 여러개의 region을 포함할수있다.
 * end_rgn + 1은 iterator과정에서 종료조건을 원활히 찾기 위함이다.
 */
		} else {
			/* @rgn is fully contained, record it */
			if (!*end_rgn)
				*start_rgn = idx;
			*end_rgn = idx + 1;
		}
	}

	return 0;
}
/*
 * IAMROOT, 2021.10.23:
 * - base ~ base + size 삭제를 진행한다.
 */
static int __init_memblock memblock_remove_range(struct memblock_type *type,
					  phys_addr_t base, phys_addr_t size)
{
	int start_rgn, end_rgn;
	int i, ret;

	ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = end_rgn - 1; i >= start_rgn; i--)
		memblock_remove_region(type, i);
	return 0;
}

/*
 * IAMROOT, 2021.10.23:
 * - base ~ base + size 주소를 지운다.
 *
 *   실제론 별로 호출될일이없다. 산업용장비에서 memory를 물리적으로(hotplug)
 *   제거하거나 guest os에 할당했던 메모리를 반환받는 상황등에서
 *   발생할수있다.
 *
 *   memblock_add의 반대.
 */
int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_remove_range(&memblock.memory, base, size);
}

/**
 * memblock_free - free boot memory block
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
/*
 * IAMROOT, 2021.10.23:
 * - reserved 영역을 free하는게 보인다.
 *   memblock_alloc의 반대.
 */
int __init_memblock memblock_free(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	kmemleak_free_part_phys(base, size);
	return memblock_remove_range(&memblock.reserved, base, size);
}
/*
 * IAMROOT, 2021.10.23:
 * - memblock_reserve는 memblock_add_range에 type만 바꿔서 하는게 보인다.
 */
int __init_memblock memblock_reserve(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_add_range(&memblock.reserved, base, size, MAX_NUMNODES, 0);
}

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
int __init_memblock memblock_physmem_add(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_add_range(&physmem, base, size, MAX_NUMNODES, 0);
}
#endif

/**
 * memblock_setclr_flag - set or clear flag for a memory region
 * @base: base address of the region
 * @size: size of the region
 * @set: set or clear the flag
 * @flag: the flag to udpate
 *
 * This function isolates region [@base, @base + @size), and sets/clears flag
 *
 * Return: 0 on success, -errno on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - isolate로 해당 범위에 대한 memblock을 선별한뒤 flag를 고치고
 *   merge가 가능한 memblock은 merge한다.
 */
static int __init_memblock memblock_setclr_flag(phys_addr_t base,
				phys_addr_t size, int set, int flag)
{
	struct memblock_type *type = &memblock.memory;
	int i, ret, start_rgn, end_rgn;

	ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = start_rgn; i < end_rgn; i++) {
		struct memblock_region *r = &type->regions[i];

		if (set)
			r->flags |= flag;
		else
			r->flags &= ~flag;
	}

	memblock_merge_regions(type);
	return 0;
}

/**
 * memblock_mark_hotplug - Mark hotpluggable memory with flag MEMBLOCK_HOTPLUG.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_hotplug(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(base, size, 1, MEMBLOCK_HOTPLUG);
}

/**
 * memblock_clear_hotplug - Clear flag MEMBLOCK_HOTPLUG for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_clear_hotplug(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(base, size, 0, MEMBLOCK_HOTPLUG);
}

/**
 * memblock_mark_mirror - Mark mirrored memory with flag MEMBLOCK_MIRROR.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_mirror(phys_addr_t base, phys_addr_t size)
{
	system_has_some_mirror = true;

	return memblock_setclr_flag(base, size, 1, MEMBLOCK_MIRROR);
}

/**
 * memblock_mark_nomap - Mark a memory region with flag MEMBLOCK_NOMAP.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
/*
 * IAMROOT, 2021.10.30:
 * - mapping을 하지 말라는 flag를 기존 flag에 더한다.
 */
int __init_memblock memblock_mark_nomap(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(base, size, 1, MEMBLOCK_NOMAP);
}

/**
 * memblock_clear_nomap - Clear flag MEMBLOCK_NOMAP for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(base, size, 0, MEMBLOCK_NOMAP);
}

static bool should_skip_region(struct memblock_type *type,
			       struct memblock_region *m,
			       int nid, int flags)
{
	int m_nid = memblock_get_region_node(m);

	/* we never skip regions when iterating memblock.reserved or physmem */
	if (type != memblock_memory)
		return false;

	/* only memory regions are associated with nodes, check it */
	if (nid != NUMA_NO_NODE && nid != m_nid)
		return true;

	/* skip hotpluggable memory regions if needed */
	if (movable_node_is_enabled() && memblock_is_hotpluggable(m))
		return true;

	/* if we want mirror memory skip non-mirror memory regions */
	if ((flags & MEMBLOCK_MIRROR) && !memblock_is_mirror(m))
		return true;

	/* skip nomap memory unless we were asked for it explicitly */
	if (!(flags & MEMBLOCK_NOMAP) && memblock_is_nomap(m))
		return true;
/*
 * IAMROOT, 2021.10.23:
 * - 결국 normal memory만 skip하지 말라는 의미
 */
	return false;
}

/**
 * __next_mem_range - next function for for_each_free_mem_range() etc.
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Find the first area from *@idx which matches @nid, fill the out
 * parameters, and update *@idx for the next iteration.  The lower 32bit of
 * *@idx contains index into type_a and the upper 32bit indexes the
 * areas before each region in type_b.	For example, if type_b regions
 * look like the following,
 *
 *	0:[0-16), 1:[32-48), 2:[128-130)
 *
 * The upper 32bit indexes the following regions.
 *
 *	0:[0-0), 1:[16-32), 2:[48-128), 3:[130-MAX)
 *
 * As both region arrays are sorted, the function advances the two indices
 * in lockstep and returns each intersection.
 */
/*
 * IAMROOT, 2021.10.23:
 * - arm64에서는 기본적으로 reverse로 search.
 */
void __next_mem_range(u64 *idx, int nid, enum memblock_flags flags,
		      struct memblock_type *type_a,
		      struct memblock_type *type_b, phys_addr_t *out_start,
		      phys_addr_t *out_end, int *out_nid)
{
	int idx_a = *idx & 0xffffffff;
	int idx_b = *idx >> 32;

	if (WARN_ONCE(nid == MAX_NUMNODES,
	"Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
		nid = NUMA_NO_NODE;

	for (; idx_a < type_a->cnt; idx_a++) {
		struct memblock_region *m = &type_a->regions[idx_a];

		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;
		int	    m_nid = memblock_get_region_node(m);

		if (should_skip_region(type_a, m, nid, flags))
			continue;

		if (!type_b) {
			if (out_start)
				*out_start = m_start;
			if (out_end)
				*out_end = m_end;
			if (out_nid)
				*out_nid = m_nid;
			idx_a++;
			*idx = (u32)idx_a | (u64)idx_b << 32;
			return;
		}

		/* scan areas before each reservation */
		for (; idx_b < type_b->cnt + 1; idx_b++) {
			struct memblock_region *r;
			phys_addr_t r_start;
			phys_addr_t r_end;

			r = &type_b->regions[idx_b];
			r_start = idx_b ? r[-1].base + r[-1].size : 0;
			r_end = idx_b < type_b->cnt ?
				r->base : PHYS_ADDR_MAX;

			/*
			 * if idx_b advanced past idx_a,
			 * break out to advance idx_a
			 */
			if (r_start >= m_end)
				break;
			/* if the two regions intersect, we're done */
			if (m_start < r_end) {
				if (out_start)
					*out_start =
						max(m_start, r_start);
				if (out_end)
					*out_end = min(m_end, r_end);
				if (out_nid)
					*out_nid = m_nid;
				/*
				 * The region which ends first is
				 * advanced for the next iteration.
				 */
				if (m_end <= r_end)
					idx_a++;
				else
					idx_b++;
				*idx = (u32)idx_a | (u64)idx_b << 32;
				return;
			}
		}
	}

	/* signal end of iteration */
	*idx = ULLONG_MAX;
}

/**
 * __next_mem_range_rev - generic next function for for_each_*_range_rev()
 *
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Finds the next range from type_a which is not marked as unsuitable
 * in type_b.
 *
 * Reverse of __next_mem_range().
 */
/*
 * IAMROOT, 2021.10.23:
 * - memory region과 reserve region에서 free영역을 찾아서 해당
 *   free영역의 start, end, nid를 가져온다.
 */
void __init_memblock __next_mem_range_rev(u64 *idx, int nid,
					  enum memblock_flags flags,
					  struct memblock_type *type_a,
					  struct memblock_type *type_b,
					  phys_addr_t *out_start,
					  phys_addr_t *out_end, int *out_nid)
{
/*
 * IAMROOT, 2021.10.23:
 * - 이 for문에서 idx 0 ~ 31bit는 type_a에 대한 idx,
 *   32 ~ 63bit는 tpye+b에 대한 idx로 사용한다.
 *
 * - type_a는 memory region, type_b는 reserved region이다.
 */
	int idx_a = *idx & 0xffffffff;
	int idx_b = *idx >> 32;

	if (WARN_ONCE(nid == MAX_NUMNODES, "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
		nid = NUMA_NO_NODE;
/*
 * IAMROOT, 2021.10.23:
 * - 첫진입시 idx가 끝주소면, memblock의 제일 마지막을 지정하기 위함.
 * - type_b가 있다는건 reserved region도 loop를 돌아야된다는것이므로
 *   reserved region의 마지막 memblock을 설정해주고 그게 아니면 사용하지
 *   않는의미로 그냥 0을 넣는다.
 *
 * - memory는 실제 존재하는 영역으로 사용하므로 -1을 하고(실제 마지막영역)
 *   reserved의 경우에는 reserved의 반대편(free)부터 검색을 하므로 마지막
 *   블럭의 윗공간이 필요하기 때문에 -1을 사용할 필요없다.
 */
	if (*idx == (u64)ULLONG_MAX) {
		idx_a = type_a->cnt - 1;
		if (type_b != NULL)
			idx_b = type_b->cnt;
		else
			idx_b = 0;
	}
/*
 * IAMROOT, 2021.10.23:
 * - type_a에 대한, 즉 memory영역을 reverse 탐색을 진행한다.
 */
	for (; idx_a >= 0; idx_a--) {
		struct memblock_region *m = &type_a->regions[idx_a];

		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;
		int m_nid = memblock_get_region_node(m);

		if (should_skip_region(type_a, m, nid, flags))
			continue;
/*
 * IAMROOT, 2021.10.23:
 * - reserve 가 없으면 결과값을 설정하고 종료한다.
 */
		if (!type_b) {
			if (out_start)
				*out_start = m_start;
			if (out_end)
				*out_end = m_end;
			if (out_nid)
				*out_nid = m_nid;
			idx_a--;
			*idx = (u32)idx_a | (u64)idx_b << 32;
			return;
		}
/*
 * IAMROOT, 2021.10.23:
 * - reserve region을 reverse 탐색한다.
 */
		/* scan areas before each reservation */
		for (; idx_b >= 0; idx_b--) {
			struct memblock_region *r;
			phys_addr_t r_start;
			phys_addr_t r_end;
/*
 * IAMROOT, 2021.10.23:
 *
 * 2개의 region이라면 다음과 같다.
 *
 * 높은주소
 * ===========================
 * +----------+ 
 * |          |         
 * | r(b)     |         
 * |          |         
 * +----------+ r_end or PHYS_ADDR_MAX
 *              
 * (free 공간)
 *                      
 * +----------+ r_start 
 * |          |         
 * | r(b-1)   |         
 * |          |         
 * +----------+ 
 * ===========================
 * 낮은주소
 *
 * 최초의 경우에는 r(b)가 없는 상태인데 이 경우 그냥 주소 끝값인
 * PHYS_ADDR_MAX을 가져온다.
 * 
 * 이렇게 되서 r_start ~ r_end 공간이 찾아지게 되는것.
 */
			r = &type_b->regions[idx_b];
			r_start = idx_b ? r[-1].base + r[-1].size : 0;
			r_end = idx_b < type_b->cnt ?
				r->base : PHYS_ADDR_MAX;
			/*
			 * if idx_b advanced past idx_a,
			 * break out to advance idx_a
			 */
/*
 * IAMROOT, 2021.10.23:
 * memory가 없는 공간이 탐색됬으므로 다음 memory 영역으로 탐색
 */
			if (r_end <= m_start)
				break;
/*
 * IAMROOT, 2021.10.23:
 *
 * 다음 예제에서 어떻게 out 값들이 수정되는지 살펴보면
 *
 * m_end    +---------+   
 *          |         |  +-------+ r_end
 *          | memory  |         
 *          |         |    free 
 * m_start  +---------+  
 *
 *                       +-------+ r_start
 *
 * 수정후 다음과 같이 된다.
 *
 * m_end    +---------+   
 *          |         |  +-------+ r_end <-- out_end
 *          | memory  |         
 *          |         |    out
 * m_start  +---------+  <------------------ out_start
 *
 *                       +-------+ r_start
 */
			/* if the two regions intersect, we're done */
			if (m_end > r_start) {
				if (out_start)
					*out_start = max(m_start, r_start);
				if (out_end)
					*out_end = min(m_end, r_end);
				if (out_nid)
					*out_nid = m_nid;
/*
 * IAMROOT, 2021.10.23:
 * - m_start >= r_start
 * 해당 memory region이 끝난경우 다음 memory region으로 이동.
 *
 *                        ...
 * m_end    +---------+  | rsv   | 
 *          | memory  |  +-------+ r_end <-- out_end
 *          | 탐색됨  |           
 *          | 탐색됨  |       
 * m_start  +---------+  <----------------- out_start
 *
 *                       +-------+ r_start
 *                       | rsv   |
 *                        ...
 *
 * (memory가 전부 탐색되어 다음 memory region으로 이동)
 *
 * - m_start < r_start
 *
 * 해당 free에서 memory 탐색을 할게 없어 다음 free영역을 찾아야되므로
 * reserve region이동
 *
 *                        ...
 * m_end    +---------+  | rsv   |
 *          |         |  +-------+ r_end   <-- out_end
 *          | memory  |         
 *          | 탐색됨  |    free
 *          |         |  +-------+ r_start <-- out_start
 *          |         |  | rsv   |
 * m_start  +---------+   ...
 *
 * 
 */
				if (m_start >= r_start)
					idx_a--;
				else
					idx_b--;
				*idx = (u32)idx_a | (u64)idx_b << 32;
				return;
			}
		}
	}
	/* signal end of iteration */
	*idx = ULLONG_MAX;
}

/*
 * Common iterator interface used to define for_each_mem_pfn_range().
 */
void __init_memblock __next_mem_pfn_range(int *idx, int nid,
				unsigned long *out_start_pfn,
				unsigned long *out_end_pfn, int *out_nid)
{
	struct memblock_type *type = &memblock.memory;
	struct memblock_region *r;
	int r_nid;

	while (++*idx < type->cnt) {
		r = &type->regions[*idx];
		r_nid = memblock_get_region_node(r);

		if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
			continue;
		if (nid == MAX_NUMNODES || nid == r_nid)
			break;
	}
	if (*idx >= type->cnt) {
		*idx = -1;
		return;
	}

	if (out_start_pfn)
		*out_start_pfn = PFN_UP(r->base);
	if (out_end_pfn)
		*out_end_pfn = PFN_DOWN(r->base + r->size);
	if (out_nid)
		*out_nid = r_nid;
}

/**
 * memblock_set_node - set node ID on memblock regions
 * @base: base of area to set node ID for
 * @size: size of area to set node ID for
 * @type: memblock type to set node ID for
 * @nid: node ID to set
 *
 * Set the nid of memblock @type regions in [@base, @base + @size) to @nid.
 * Regions which cross the area boundaries are split as necessary.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - 요청된 범위의 memblock의 nid를 교체후 merge
 */
int __init_memblock memblock_set_node(phys_addr_t base, phys_addr_t size,
				      struct memblock_type *type, int nid)
{
#ifdef CONFIG_NEED_MULTIPLE_NODES
	int start_rgn, end_rgn;
	int i, ret;

	ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = start_rgn; i < end_rgn; i++)
		memblock_set_region_node(&type->regions[i], nid);

	memblock_merge_regions(type);
#endif
	return 0;
}

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
/**
 * __next_mem_pfn_range_in_zone - iterator for for_each_*_range_in_zone()
 *
 * @idx: pointer to u64 loop variable
 * @zone: zone in which all of the memory blocks reside
 * @out_spfn: ptr to ulong for start pfn of the range, can be %NULL
 * @out_epfn: ptr to ulong for end pfn of the range, can be %NULL
 *
 * This function is meant to be a zone/pfn specific wrapper for the
 * for_each_mem_range type iterators. Specifically they are used in the
 * deferred memory init routines and as such we were duplicating much of
 * this logic throughout the code. So instead of having it in multiple
 * locations it seemed like it would make more sense to centralize this to
 * one new iterator that does everything they need.
 */
void __init_memblock
__next_mem_pfn_range_in_zone(u64 *idx, struct zone *zone,
			     unsigned long *out_spfn, unsigned long *out_epfn)
{
	int zone_nid = zone_to_nid(zone);
	phys_addr_t spa, epa;
	int nid;

	__next_mem_range(idx, zone_nid, MEMBLOCK_NONE,
			 &memblock.memory, &memblock.reserved,
			 &spa, &epa, &nid);

	while (*idx != U64_MAX) {
		unsigned long epfn = PFN_DOWN(epa);
		unsigned long spfn = PFN_UP(spa);

		/*
		 * Verify the end is at least past the start of the zone and
		 * that we have at least one PFN to initialize.
		 */
		if (zone->zone_start_pfn < epfn && spfn < epfn) {
			/* if we went too far just stop searching */
			if (zone_end_pfn(zone) <= spfn) {
				*idx = U64_MAX;
				break;
			}

			if (out_spfn)
				*out_spfn = max(zone->zone_start_pfn, spfn);
			if (out_epfn)
				*out_epfn = min(zone_end_pfn(zone), epfn);

			return;
		}

		__next_mem_range(idx, zone_nid, MEMBLOCK_NONE,
				 &memblock.memory, &memblock.reserved,
				 &spa, &epa, &nid);
	}

	/* signal end of iteration */
	if (out_spfn)
		*out_spfn = ULONG_MAX;
	if (out_epfn)
		*out_epfn = 0;
}

#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

/**
 * memblock_alloc_range_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @start: the lower bound of the memory region to allocate (phys address)
 * @end: the upper bound of the memory region to allocate (phys address)
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @exact_nid: control the allocation fall back to other nodes
 *
 * The allocation is performed from memory region limited by
 * memblock.current_limit if @end == %MEMBLOCK_ALLOC_ACCESSIBLE.
 *
 * If the specified node can not hold the requested memory and @exact_nid
 * is false, the allocation falls back to any node in the system.
 *
 * For systems with memory mirroring, the allocation is attempted first
 * from the regions with mirroring enabled and then retried from any
 * memory region.
 *
 * In addition, function sets the min_count to 0 using kmemleak_alloc_phys for
 * allocated boot memory block, so that it is never reported as leaks.
 *
 * Return:
 * Physical address of allocated memory block on success, %0 on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * 인자에 올수있는 define에 대한 정리.
 * - start
 *   MEMBLOCK_LOW_LIMIT : 0
 *
 * - end
 *   MEMBLOCK_ALLOC_ACCESSIBLE : 0. current_limit 를 사용하라는것
 *   MEMBLOCK_ALLOC_KASAN : 1
 *   MEMBLOCK_ALLOC_ANYWHERE : max
 */
phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
					phys_addr_t align, phys_addr_t start,
					phys_addr_t end, int nid,
					bool exact_nid)
{
/*
 * IAMROOT, 2021.10.23:
 * - system이 half mirror 운용중 인지에 대한 flags.
 * - full mirror면 어짜피 system mirror가 전체로 mirror로 운용되므로 딱히
 *   kernel이 알필요가 없을것이다.
 */
	enum memblock_flags flags = choose_memblock_flags();
	phys_addr_t found;

/*
 * IAMROOT, 2021.10.23:
 * - Any node의 경우 옛날엔 MAX_NUMNODES(16)을 사용햇었다.
 *   지금은 NUMA_NO_NODE(-1)을 사용한다.
 */
	if (WARN_ONCE(nid == MAX_NUMNODES, "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
		nid = NUMA_NO_NODE;

	if (!align) {
		/* Can't use WARNs this early in boot on powerpc */
		dump_stack();
		align = SMP_CACHE_BYTES;
	}

again:
	found = memblock_find_in_range_node(size, align, start, end, nid,
					    flags);
/*
 * IAMROOT, 2021.10.23:
 * - 할당할수 있는 영역을 찾고, reserve에 성공했으면 done.
 */
	if (found && !memblock_reserve(found, size))
		goto done;
/*
 * IAMROOT, 2021.10.23:
 * - nid가 지정되있으면서 반드시 할필요가 없다면 nid를 그냥 Any로 해서
 *   전체 node에서 다시 검색.
 */
	if (nid != NUMA_NO_NODE && !exact_nid) {
		found = memblock_find_in_range_node(size, align, start,
						    end, NUMA_NO_NODE,
						    flags);
		if (found && !memblock_reserve(found, size))
			goto done;
	}
/*
 * IAMROOT, 2021.10.23:
 * - flag가 mirror인 경우에만 다시 한번 빼보고 again한다.
 */
	if (flags & MEMBLOCK_MIRROR) {
		flags &= ~MEMBLOCK_MIRROR;
		pr_warn("Could not allocate %pap bytes of mirrored memory\n",
			&size);
		goto again;
	}
/*
 * IAMROOT, 2021.10.23:
 * - 실패
 */
	return 0;

done:
	/* Skip kmemleak for kasan_init() due to high volume. */
/*
 * IAMROOT, 2021.10.23:
 * - kasan_init이 호출되는 경우는 pass.
 */
	if (end != MEMBLOCK_ALLOC_KASAN)
		/*
		 * The min_count is set to 0 so that memblock allocated
		 * blocks are never reported as leaks. This is because many
		 * of these blocks are only referred via the physical
		 * address which is not looked up by kmemleak.
		 */
		kmemleak_alloc_phys(found, size, 0, 0);

	return found;
}

/**
 * memblock_phys_alloc_range - allocate a memory block inside specified range
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @start: the lower bound of the memory region to allocate (physical address)
 * @end: the upper bound of the memory region to allocate (physical address)
 *
 * Allocate @size bytes in the between @start and @end.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - alloc 함수는 대부분 가상주소를 return하지만 이 함수는 물리주소를
 *   return 한다.
 */
phys_addr_t __init memblock_phys_alloc_range(phys_addr_t size,
					     phys_addr_t align,
					     phys_addr_t start,
					     phys_addr_t end)
{
	return memblock_alloc_range_nid(size, align, start, end, NUMA_NO_NODE,
					false);
}

/**
 * memblock_phys_alloc_try_nid - allocate a memory block from specified MUMA node
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Allocates memory block from the specified NUMA node. If the node
 * has no available memory, attempts to allocated from any node in the
 * system.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 */
phys_addr_t __init memblock_phys_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	return memblock_alloc_range_nid(size, align, 0,
					MEMBLOCK_ALLOC_ACCESSIBLE, nid, false);
}

/**
 * memblock_alloc_internal - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region to allocate (phys address)
 * @max_addr: the upper bound of the memory region to allocate (phys address)
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @exact_nid: control the allocation fall back to other nodes
 *
 * Allocates memory block using memblock_alloc_range_nid() and
 * converts the returned physical address to virtual.
 *
 * The @min_addr limit is dropped if it can not be satisfied and the allocation
 * will fall back to memory below @min_addr. Other constraints, such
 * as node and mirrored memory will be handled again in
 * memblock_alloc_range_nid().
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - exact_nid는 보통은 false고 memblock_alloc_exact_nid_raw 함수에서만
 *   true로 들어오는게 보인다.
 */
static void * __init memblock_alloc_internal(
				phys_addr_t size, phys_addr_t align,
				phys_addr_t min_addr, phys_addr_t max_addr,
				int nid, bool exact_nid)
{
	phys_addr_t alloc;

	/*
	 * Detect any accidental use of these APIs after slab is ready, as at
	 * this moment memblock may be deinitialized already and its
	 * internal data may be destroyed (after execution of memblock_free_all)
	 */
/*
 * IAMROOT, 2021.10.23:
 * - slab 이 사용가능하다면 memblock api을 썻어도 그냥 slab으로 써버리는게
 *   확인된다.
 */
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, nid);

	if (max_addr > memblock.current_limit)
		max_addr = memblock.current_limit;

	alloc = memblock_alloc_range_nid(size, align, min_addr, max_addr, nid,
					exact_nid);

	/* retry allocation without lower limit */
	if (!alloc && min_addr)
		alloc = memblock_alloc_range_nid(size, align, 0, max_addr, nid,
						exact_nid);

	if (!alloc)
		return NULL;
/*
 * IAMROOT, 2021.10.23:
 * paging init이 끝난 alloc함수들은 전부 가상주소로 return 한다.
 */
	return phys_to_virt(alloc);
}

/**
 * memblock_alloc_exact_nid_raw - allocate boot memory block on the exact node
 * without zeroing memory
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. Does not zero allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init memblock_alloc_exact_nid_raw(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	void *ptr;

	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);

	ptr = memblock_alloc_internal(size, align,
					   min_addr, max_addr, nid, true);
	if (ptr && size > 0)
		page_init_poison(ptr, size);

	return ptr;
}

/**
 * memblock_alloc_try_nid_raw - allocate boot memory block without zeroing
 * memory and without panicking
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. Does not zero allocated memory, does not panic if request
 * cannot be satisfied.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - memset으로 초기화를 안시키고 바로 반환 한다.
 */
void * __init memblock_alloc_try_nid_raw(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	void *ptr;

	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);

	ptr = memblock_alloc_internal(size, align,
					   min_addr, max_addr, nid, false);
	if (ptr && size > 0)
		page_init_poison(ptr, size);

	return ptr;
}

/**
 * memblock_alloc_try_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. This function zeroes the allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
/*
 * IAMROOT, 2021.10.23:
 * - 해당 요청에 따른 memory를 할당받아온다. 가상주소 return
 */
void * __init memblock_alloc_try_nid(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	void *ptr;

	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);
/*
 * IAMROOT, 2021.10.23:
 * - ptr은 kernel에서 대부분 가상주소다.
 *   바로 다음줄에서 memset을 사용하는게 보이고, 즉 현재시점부터는
 *   할당받은 메모리를 바로 사용할수있는(리니어 매핑) 상태가 되있는것을
 *   알 수 있다.
 */
	ptr = memblock_alloc_internal(size, align,
					   min_addr, max_addr, nid, false);
	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

/**
 * __memblock_free_late - free pages directly to buddy allocator
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * This is only useful when the memblock allocator has already been torn
 * down, but we are still initializing the system.  Pages are released directly
 * to the buddy allocator.
 */
void __init __memblock_free_late(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t cursor, end;

	end = base + size - 1;
	memblock_dbg("%s: [%pa-%pa] %pS\n",
		     __func__, &base, &end, (void *)_RET_IP_);
	kmemleak_free_part_phys(base, size);
	cursor = PFN_UP(base);
	end = PFN_DOWN(base + size);

	for (; cursor < end; cursor++) {
		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
		totalram_pages_inc();
	}
}

/*
 * Remaining API functions
 */

phys_addr_t __init_memblock memblock_phys_mem_size(void)
{
	return memblock.memory.total_size;
}

phys_addr_t __init_memblock memblock_reserved_size(void)
{
	return memblock.reserved.total_size;
}

/* lowest address */
/*
 * IAMROOT, 2021.10.25:
 * - setup_machine_fdt -> early_init_dt_scan -> early_init_dt_scan_memory
 *   을 통해서 dt에서 읽은 memory 값으로 최초에 memblock에 추가가 될것이다.
 */
phys_addr_t __init_memblock memblock_start_of_DRAM(void)
{
	return memblock.memory.regions[0].base;
}

phys_addr_t __init_memblock memblock_end_of_DRAM(void)
{
	int idx = memblock.memory.cnt - 1;

	return (memblock.memory.regions[idx].base + memblock.memory.regions[idx].size);
}

static phys_addr_t __init_memblock __find_max_addr(phys_addr_t limit)
{
	phys_addr_t max_addr = PHYS_ADDR_MAX;
	struct memblock_region *r;

	/*
	 * translate the memory @limit size into the max address within one of
	 * the memory memblock regions, if the @limit exceeds the total size
	 * of those regions, max_addr will keep original value PHYS_ADDR_MAX
	 */
	for_each_mem_region(r) {
		if (limit <= r->size) {
			max_addr = r->base + limit;
			break;
		}
		limit -= r->size;
	}

	return max_addr;
}

void __init memblock_enforce_memory_limit(phys_addr_t limit)
{
	phys_addr_t max_addr;

	if (!limit)
		return;

	max_addr = __find_max_addr(limit);

	/* @limit exceeds the total size of the memory, do nothing */
	if (max_addr == PHYS_ADDR_MAX)
		return;

	/* truncate both memory and reserved regions */
	memblock_remove_range(&memblock.memory, max_addr,
			      PHYS_ADDR_MAX);
	memblock_remove_range(&memblock.reserved, max_addr,
			      PHYS_ADDR_MAX);
}
/*
 * IAMROOT, 2021.10.23:
 * - 요청된 범위이외의 영역을 전부 지운다.
 */
void __init memblock_cap_memory_range(phys_addr_t base, phys_addr_t size)
{
	int start_rgn, end_rgn;
	int i, ret;

	if (!size)
		return;

	ret = memblock_isolate_range(&memblock.memory, base, size,
						&start_rgn, &end_rgn);
	if (ret)
		return;

	/* remove all the MAP regions */
	for (i = memblock.memory.cnt - 1; i >= end_rgn; i--)
		if (!memblock_is_nomap(&memblock.memory.regions[i]))
			memblock_remove_region(&memblock.memory, i);

	for (i = start_rgn - 1; i >= 0; i--)
		if (!memblock_is_nomap(&memblock.memory.regions[i]))
			memblock_remove_region(&memblock.memory, i);

	/* truncate the reserved regions */
	memblock_remove_range(&memblock.reserved, 0, base);
	memblock_remove_range(&memblock.reserved,
			base + size, PHYS_ADDR_MAX);
}

void __init memblock_mem_limit_remove_map(phys_addr_t limit)
{
	phys_addr_t max_addr;

	if (!limit)
		return;

	max_addr = __find_max_addr(limit);

	/* @limit exceeds the total size of the memory, do nothing */
	if (max_addr == PHYS_ADDR_MAX)
		return;

	memblock_cap_memory_range(0, max_addr);
}

/*
 * IAMROOT, 2021.10.23:
 * - 해당 addr이 존재하는지 binsearch한다. 반한되는값은 memblock index
 */
static int __init_memblock memblock_search(struct memblock_type *type, phys_addr_t addr)
{
	unsigned int left = 0, right = type->cnt;

	do {
		unsigned int mid = (right + left) / 2;

		if (addr < type->regions[mid].base)
			right = mid;
		else if (addr >= (type->regions[mid].base +
				  type->regions[mid].size))
			left = mid + 1;
		else
			return mid;
	} while (left < right);
	return -1;
}

bool __init_memblock memblock_is_reserved(phys_addr_t addr)
{
	return memblock_search(&memblock.reserved, addr) != -1;
}

bool __init_memblock memblock_is_memory(phys_addr_t addr)
{
	return memblock_search(&memblock.memory, addr) != -1;
}

bool __init_memblock memblock_is_map_memory(phys_addr_t addr)
{
	int i = memblock_search(&memblock.memory, addr);

	if (i == -1)
		return false;
	return !memblock_is_nomap(&memblock.memory.regions[i]);
}

int __init_memblock memblock_search_pfn_nid(unsigned long pfn,
			 unsigned long *start_pfn, unsigned long *end_pfn)
{
	struct memblock_type *type = &memblock.memory;
	int mid = memblock_search(type, PFN_PHYS(pfn));

	if (mid == -1)
		return -1;

	*start_pfn = PFN_DOWN(type->regions[mid].base);
	*end_pfn = PFN_DOWN(type->regions[mid].base + type->regions[mid].size);

	return memblock_get_region_node(&type->regions[mid]);
}

/**
 * memblock_is_region_memory - check if a region is a subset of memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base + @size) is a subset of a memory block.
 *
 * Return:
 * 0 if false, non-zero if true
 */
bool __init_memblock memblock_is_region_memory(phys_addr_t base, phys_addr_t size)
{
	int idx = memblock_search(&memblock.memory, base);
	phys_addr_t end = base + memblock_cap_size(base, &size);

	if (idx == -1)
		return false;
	return (memblock.memory.regions[idx].base +
		 memblock.memory.regions[idx].size) >= end;
}

/**
 * memblock_is_region_reserved - check if a region intersects reserved memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base + @size) intersects a reserved
 * memory block.
 *
 * Return:
 * True if they intersect, false if not.
 */
/*
 * IAMROOT, 2021.10.23:
 * - reseved 영역에서 해당 범위가 겹치는지 여부를 반환.
 */
bool __init_memblock memblock_is_region_reserved(phys_addr_t base, phys_addr_t size)
{
	memblock_cap_size(base, &size);
	return memblock_overlaps_region(&memblock.reserved, base, size);
}

/*
 * IAMROOT, 2021.10.23:
 * - 등록되있는 memory을 aligin단위로 정렬
 */
void __init_memblock memblock_trim_memory(phys_addr_t align)
{
	phys_addr_t start, end, orig_start, orig_end;
	struct memblock_region *r;

	for_each_mem_region(r) {
		orig_start = r->base;
		orig_end = r->base + r->size;
		start = round_up(orig_start, align);
		end = round_down(orig_end, align);

		if (start == orig_start && end == orig_end)
			continue;

		if (start < end) {
			r->base = start;
			r->size = end - start;
		} else {
			memblock_remove_region(&memblock.memory,
					       r - memblock.memory.regions);
			r--;
		}
	}
}

void __init_memblock memblock_set_current_limit(phys_addr_t limit)
{
	memblock.current_limit = limit;
}

phys_addr_t __init_memblock memblock_get_current_limit(void)
{
	return memblock.current_limit;
}

static void __init_memblock memblock_dump(struct memblock_type *type)
{
	phys_addr_t base, end, size;
	enum memblock_flags flags;
	int idx;
	struct memblock_region *rgn;

	pr_info(" %s.cnt  = 0x%lx\n", type->name, type->cnt);

	for_each_memblock_type(idx, type, rgn) {
		char nid_buf[32] = "";

		base = rgn->base;
		size = rgn->size;
		end = base + size - 1;
		flags = rgn->flags;
#ifdef CONFIG_NEED_MULTIPLE_NODES
		if (memblock_get_region_node(rgn) != MAX_NUMNODES)
			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
				 memblock_get_region_node(rgn));
#endif
		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
			type->name, idx, &base, &end, &size, nid_buf, flags);
	}
}

static void __init_memblock __memblock_dump_all(void)
{
	pr_info("MEMBLOCK configuration:\n");
	pr_info(" memory size = %pa reserved size = %pa\n",
		&memblock.memory.total_size,
		&memblock.reserved.total_size);

	memblock_dump(&memblock.memory);
	memblock_dump(&memblock.reserved);
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
	memblock_dump(&physmem);
#endif
}

/*
 * IAMROOT, 2021.10.23:
 * - command line에 memblock=debug param이 지정된 상태에서 동작하며
 *   해당 함수는 bootmem_init 마지막에서 호출해준다.
 */
void __init_memblock memblock_dump_all(void)
{
	if (memblock_debug)
		__memblock_dump_all();
}

/*
 * IAMROOT, 2021.10.23:
 * - paging init이 완료 되고나서 memblock alloc이 사용가능해지면
 *   호출 된다.
 */
void __init memblock_allow_resize(void)
{
	memblock_can_resize = 1;
}

/*
 * IAMROOT, 2021.10.23:
 * - command line에 memblock=debug 와 같이 입력이 되어있으면 debug를 set한다.
 */
static int __init early_memblock(char *p)
{
	if (p && strstr(p, "debug"))
		memblock_debug = 1;
	return 0;
}
early_param("memblock", early_memblock);

static void __init __free_pages_memory(unsigned long start, unsigned long end)
{
	int order;

	while (start < end) {
		order = min(MAX_ORDER - 1UL, __ffs(start));

		while (start + (1UL << order) > end)
			order--;

		memblock_free_pages(pfn_to_page(start), start, order);

		start += (1UL << order);
	}
}

static unsigned long __init __free_memory_core(phys_addr_t start,
				 phys_addr_t end)
{
	unsigned long start_pfn = PFN_UP(start);
	unsigned long end_pfn = min_t(unsigned long,
				      PFN_DOWN(end), max_low_pfn);

	if (start_pfn >= end_pfn)
		return 0;

	__free_pages_memory(start_pfn, end_pfn);

	return end_pfn - start_pfn;
}

static unsigned long __init free_low_memory_core_early(void)
{
	unsigned long count = 0;
	phys_addr_t start, end;
	u64 i;

	memblock_clear_hotplug(0, -1);

	for_each_reserved_mem_range(i, &start, &end)
		reserve_bootmem_region(start, end);

	/*
	 * We need to use NUMA_NO_NODE instead of NODE_DATA(0)->node_id
	 *  because in some case like Node0 doesn't have RAM installed
	 *  low ram will be on Node1
	 */
	for_each_free_mem_range(i, NUMA_NO_NODE, MEMBLOCK_NONE, &start, &end,
				NULL)
		count += __free_memory_core(start, end);

	return count;
}

static int reset_managed_pages_done __initdata;

void reset_node_managed_pages(pg_data_t *pgdat)
{
	struct zone *z;

	for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
		atomic_long_set(&z->managed_pages, 0);
}

void __init reset_all_zones_managed_pages(void)
{
	struct pglist_data *pgdat;

	if (reset_managed_pages_done)
		return;

	for_each_online_pgdat(pgdat)
		reset_node_managed_pages(pgdat);

	reset_managed_pages_done = 1;
}

/**
 * memblock_free_all - release free pages to the buddy allocator
 *
 * Return: the number of pages actually released.
 */
unsigned long __init memblock_free_all(void)
{
	unsigned long pages;

	reset_all_zones_managed_pages();

	pages = free_low_memory_core_early();
	totalram_pages_add(pages);

	return pages;
}

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_ARCH_KEEP_MEMBLOCK)
/*
 * IAMROOT, 2021.10.23:
 *
 * - kernel에서 debugfs 관련 config를 on해서 /sys/kernel/debug 등을 사용해서
 *   user 영역에서 확인할수있다.
 */
static int memblock_debug_show(struct seq_file *m, void *private)
{
	struct memblock_type *type = m->private;
	struct memblock_region *reg;
	int i;
	phys_addr_t end;

	for (i = 0; i < type->cnt; i++) {
		reg = &type->regions[i];
		end = reg->base + reg->size - 1;

		seq_printf(m, "%4d: ", i);
		seq_printf(m, "%pa..%pa\n", &reg->base, &end);
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(memblock_debug);

static int __init memblock_init_debugfs(void)
{
	struct dentry *root = debugfs_create_dir("memblock", NULL);

	debugfs_create_file("memory", 0444, root,
			    &memblock.memory, &memblock_debug_fops);
	debugfs_create_file("reserved", 0444, root,
			    &memblock.reserved, &memblock_debug_fops);
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
	debugfs_create_file("physmem", 0444, root, &physmem,
			    &memblock_debug_fops);
#endif

	return 0;
}
__initcall(memblock_init_debugfs);

#endif /* CONFIG_DEBUG_FS */
