/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmdebug.h>
#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>
#include <linux/topology.h>

/* The typedef is in types.h but we want the documentation here */
#if 0
/**
 * typedef gfp_t - Memory allocation flags.
 *
 * GFP flags are commonly used throughout Linux to indicate how memory
 * should be allocated.  The GFP acronym stands for get_free_pages(),
 * the underlying memory allocation function.  Not every GFP flag is
 * supported by every function which may allocate memory.  Most users
 * will want to use a plain ``GFP_KERNEL``.
 */
typedef unsigned int __bitwise gfp_t;
#endif

struct vm_area_struct;

/*
 * In case of changes, please don't forget to update
 * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
 */

/* Plain integer GFP bitmasks. Do not use this directly. */
/*
 * IAMROOT, 2022.02.12: 
 * - 밑줄3개(___)로 시작하는 gfp 플래그는 사용자가 직접 사용할 수 없다.
 *   또한 각 기능들이 하나의 비트에 대응한다.
 *
 * - zone을 결정하는 gfp 플래그는 다음과 같다.
 *   ___GFP_DMA, ___GFP_HIGHMEM, ___GFP_DMA32, ___GFP_MOVABLE
 *   플래그를 지정하지 않으면 NORMAL ZONE
 *
 * - migratetype을 결정하는 gfp 플래그는 다음과 같다.
 *   ___GFP_MOVABLE, ___GFP_RECLAIMABLE
 *   (___GFP_MOVABLE의 경우 zone과 migratetype 모두에 영향을 끼친다.)
 */
#define ___GFP_DMA		0x01u
#define ___GFP_HIGHMEM		0x02u
#define ___GFP_DMA32		0x04u
#define ___GFP_MOVABLE		0x08u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_HIGH		0x20u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_ZERO		0x100u
#define ___GFP_ATOMIC		0x200u
#define ___GFP_DIRECT_RECLAIM	0x400u
#define ___GFP_KSWAPD_RECLAIM	0x800u
#define ___GFP_WRITE		0x1000u
#define ___GFP_NOWARN		0x2000u
#define ___GFP_RETRY_MAYFAIL	0x4000u
#define ___GFP_NOFAIL		0x8000u
#define ___GFP_NORETRY		0x10000u
#define ___GFP_MEMALLOC		0x20000u
#define ___GFP_COMP		0x40000u
#define ___GFP_NOMEMALLOC	0x80000u
#define ___GFP_HARDWALL		0x100000u
#define ___GFP_THISNODE		0x200000u
#define ___GFP_ACCOUNT		0x400000u
#define ___GFP_ZEROTAGS		0x800000u
#define ___GFP_SKIP_KASAN_POISON	0x1000000u
#ifdef CONFIG_LOCKDEP
#define ___GFP_NOLOCKDEP	0x2000000u
#else
#define ___GFP_NOLOCKDEP	0
#endif
/* If the above are modified, __GFP_BITS_SHIFT may need updating */

/*
 * Physical address zone modifiers (see linux/mmzone.h - low four bits)
 *
 * Do not put any conditional on these. If necessary modify the definitions
 * without the underscores and use them consistently. The definitions here may
 * be used in bit comparisons.
 */
/*
 * IAMROOT, 2022.02.12: 
 * 존과 관련한 gfp 플래그들은 하위 4비트를 사용한다.
 * - 밑줄2개(___)로 시작하는건 두개이상의 기능을 담당할수있다.
 */
#define __GFP_DMA	((__force gfp_t)___GFP_DMA)
#define __GFP_HIGHMEM	((__force gfp_t)___GFP_HIGHMEM)
#define __GFP_DMA32	((__force gfp_t)___GFP_DMA32)
#define __GFP_MOVABLE	((__force gfp_t)___GFP_MOVABLE)  /* ZONE_MOVABLE allowed */
/*
 * IAMROOT, 2022.02.18:
 * - gfp flag에서 zone에 대한것은 순서대로 0 ~ 3bit까지로 되있다. 즉 0xf가된다.
 */
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)

/**
 * DOC: Page mobility and placement hints
 *
 * Page mobility and placement hints
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * These flags provide hints about how mobile the page is. Pages with similar
 * mobility are placed within the same pageblocks to minimise problems due
 * to external fragmentation.
 *
 * %__GFP_MOVABLE (also a zone modifier) indicates that the page can be
 * moved by page migration during memory compaction or can be reclaimed.
 *
 * %__GFP_RECLAIMABLE is used for slab allocations that specify
 * SLAB_RECLAIM_ACCOUNT and whose pages can be freed via shrinkers.
 *
 * %__GFP_WRITE indicates the caller intends to dirty the page. Where possible,
 * these pages will be spread between local zones to avoid all the dirty
 * pages being in one zone (fair zone allocation policy).
 *
 * %__GFP_HARDWALL enforces the cpuset memory allocation policy.
 *
 * %__GFP_THISNODE forces the allocation to be satisfied from the requested
 * node with no fallbacks or placement policy enforcements.
 *
 * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
 */
#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
#define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
/*
 * IAMROOT, 2022.04.16:
 * - cgroup에서 상위 그룹으로의 참조등을 차단한다.
 */
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
#define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)

/**
 * DOC: Watermark modifiers
 *
 * Watermark modifiers -- controls access to emergency reserves
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * %__GFP_HIGH indicates that the caller is high-priority and that granting
 * the request is necessary before the system can make forward progress.
 * For example, creating an IO context to clean pages.
 *
 * %__GFP_ATOMIC indicates that the caller cannot reclaim or sleep and is
 * high priority. Users are typically interrupt handlers. This may be
 * used in conjunction with %__GFP_HIGH
 *
 * %__GFP_MEMALLOC allows access to all memory. This should only be used when
 * the caller guarantees the allocation will allow more memory to be freed
 * very shortly e.g. process exiting or swapping. Users either should
 * be the MM or co-ordinating closely with the VM (e.g. swap over NFS).
 * Users of this flag have to be extremely careful to not deplete the reserve
 * completely and implement a throttling mechanism which controls the
 * consumption of the reserve based on the amount of freed memory.
 * Usage of a pre-allocated pool (e.g. mempool) should be always considered
 * before using this flag.
 *
 * %__GFP_NOMEMALLOC is used to explicitly forbid access to emergency reserves.
 * This takes precedence over the %__GFP_MEMALLOC flag if both are set.
 */
/*
 * IAMROOT, 2022.03.19:
 * - %_GFP_NOMEMALLOC를 사용하여 비상예비구역 접근을 명시적으로 금지합니다.
 *   둘 다 설정되어 있는 경우 이 플래그가 %_GFP_MEMALLOC 플래그보다 우선됩니다.
 * - emergency reserves는 watermark min에 있는 공간을 의미한다.
 * - swapping system 같은경우엔 watermark같은 memory 제한등을 안받는다. 즉
 *   emergency reserves영역등을 사용할수있고 이런 공간을 사용할수 있다는
 *   flag가 __GFP_MEMALLOC이다. 그런데 어떤 상황인 경우 이런 emergency reserves
 *   영역을 사용하지 말아야 되는데 이 flag가 __GFP_NOMEMALLOC 이다.
 */
#define __GFP_ATOMIC	((__force gfp_t)___GFP_ATOMIC)
#define __GFP_HIGH	((__force gfp_t)___GFP_HIGH)
#define __GFP_MEMALLOC	((__force gfp_t)___GFP_MEMALLOC)
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC)

/**
 * DOC: Reclaim modifiers
 *
 * Reclaim modifiers
 * ~~~~~~~~~~~~~~~~~
 * Please note that all the following flags are only applicable to sleepable
 * allocations (e.g. %GFP_NOWAIT and %GFP_ATOMIC will ignore them).
 *
 * %__GFP_IO can start physical IO.
 *
 * %__GFP_FS can call down to the low-level FS. Clearing the flag avoids the
 * allocator recursing into the filesystem which might already be holding
 * locks.
 *
 * %__GFP_DIRECT_RECLAIM indicates that the caller may enter direct reclaim.
 * This flag can be cleared to avoid unnecessary delays when a fallback
 * option is available.
 *
 * %__GFP_KSWAPD_RECLAIM indicates that the caller wants to wake kswapd when
 * the low watermark is reached and have it reclaim pages until the high
 * watermark is reached. A caller may wish to clear this flag when fallback
 * options are available and the reclaim is likely to disrupt the system. The
 * canonical example is THP allocation where a fallback is cheap but
 * reclaim/compaction may cause indirect stalls.
 *
 * %__GFP_RECLAIM is shorthand to allow/forbid both direct and kswapd reclaim.
 *
 * The default allocator behavior depends on the request size. We have a concept
 * of so called costly allocations (with order > %PAGE_ALLOC_COSTLY_ORDER).
 * !costly allocations are too essential to fail so they are implicitly
 * non-failing by default (with some exceptions like OOM victims might fail so
 * the caller still has to check for failures) while costly requests try to be
 * not disruptive and back off even without invoking the OOM killer.
 * The following three modifiers might be used to override some of these
 * implicit rules
 *
 * %__GFP_NORETRY: The VM implementation will try only very lightweight
 * memory direct reclaim to get some memory under memory pressure (thus
 * it can sleep). It will avoid disruptive actions like OOM killer. The
 * caller must handle the failure which is quite likely to happen under
 * heavy memory pressure. The flag is suitable when failure can easily be
 * handled at small cost, such as reduced throughput
 *
 * %__GFP_RETRY_MAYFAIL: The VM implementation will retry memory reclaim
 * procedures that have previously failed if there is some indication
 * that progress has been made else where.  It can wait for other
 * tasks to attempt high level approaches to freeing memory such as
 * compaction (which removes fragmentation) and page-out.
 * There is still a definite limit to the number of retries, but it is
 * a larger limit than with %__GFP_NORETRY.
 * Allocations with this flag may fail, but only when there is
 * genuinely little unused memory. While these allocations do not
 * directly trigger the OOM killer, their failure indicates that
 * the system is likely to need to use the OOM killer soon.  The
 * caller must handle failure, but can reasonably do so by failing
 * a higher-level request, or completing it only in a much less
 * efficient manner.
 * If the allocation does fail, and the caller is in a position to
 * free some non-essential memory, doing so could benefit the system
 * as a whole.
 *
 * %__GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures. The allocation could block
 * indefinitely but will never return with failure. Testing for
 * failure is pointless.
 * New users should be evaluated carefully (and the flag should be
 * used only when there is no reasonable failure policy) but it is
 * definitely preferable to use the flag rather than opencode endless
 * loop around allocator.
 * Using this flag for costly allocations is _highly_ discouraged.
 */
#define __GFP_IO	((__force gfp_t)___GFP_IO)
#define __GFP_FS	((__force gfp_t)___GFP_FS)
/*
 * IAMROOT, 2022.03.19:
 * - __GFP_DIRECT_RECLAIM을 포함한 macro
 *   __GFP_RECLAIM
 *	GFP_KERNEL
 *	GFP_NOIO
 *	GFP_NOFS
 *	GFP_USER
 *
 *   GFP_TRANSHUGE
 *
 * 위 GFP들을 사용하면 메모리 회수가 동작할수있을것이다.
 * GFP_ATOMIC같은건 interrupt등에서 동작하므로 RECLAIM이 없는것이다.
 */
#define __GFP_DIRECT_RECLAIM	((__force gfp_t)___GFP_DIRECT_RECLAIM) /* Caller can reclaim */
#define __GFP_KSWAPD_RECLAIM	((__force gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
#define __GFP_RETRY_MAYFAIL	((__force gfp_t)___GFP_RETRY_MAYFAIL)
#define __GFP_NOFAIL	((__force gfp_t)___GFP_NOFAIL)
#define __GFP_NORETRY	((__force gfp_t)___GFP_NORETRY)

/**
 * DOC: Action modifiers
 *
 * Action modifiers
 * ~~~~~~~~~~~~~~~~
 *
 * %__GFP_NOWARN suppresses allocation failure reports.
 *
 * %__GFP_COMP address compound page metadata.
 *
 * %__GFP_ZERO returns a zeroed page on success.
 *
 * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
 * __GFP_ZERO is set.
 *
 * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
 * on deallocation. Typically used for userspace pages. Currently only has an
 * effect in HW tags mode.
 */
#define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
#define __GFP_COMP	((__force gfp_t)___GFP_COMP)
#define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
#define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
#define __GFP_SKIP_KASAN_POISON	((__force gfp_t)___GFP_SKIP_KASAN_POISON)

/* Disable lockdep for GFP context tracking */
#define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)

/* Room for N __GFP_FOO bits */
#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

/**
 * DOC: Useful GFP flag combinations
 *
 * Useful GFP flag combinations
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Useful GFP flag combinations that are commonly used. It is recommended
 * that subsystems start with one of these combinations and then set/clear
 * %__GFP_FOO flags as necessary.
 *
 * %GFP_ATOMIC users can not sleep and need the allocation to succeed. A lower
 * watermark is applied to allow access to "atomic reserves".
 * The current implementation doesn't support NMI and few other strict
 * non-preemptive contexts (e.g. raw_spin_lock). The same applies to %GFP_NOWAIT.
 *
 * %GFP_KERNEL is typical for kernel-internal allocations. The caller requires
 * %ZONE_NORMAL or a lower zone for direct access but can direct reclaim.
 *
 * %GFP_KERNEL_ACCOUNT is the same as GFP_KERNEL, except the allocation is
 * accounted to kmemcg.
 *
 * %GFP_NOWAIT is for kernel allocations that should not stall for direct
 * reclaim, start physical IO or use any filesystem callback.
 *
 * %GFP_NOIO will use direct reclaim to discard clean pages or slab pages
 * that do not require the starting of any physical IO.
 * Please try to avoid using this flag directly and instead use
 * memalloc_noio_{save,restore} to mark the whole scope which cannot
 * perform any IO with a short explanation why. All allocation requests
 * will inherit GFP_NOIO implicitly.
 *
 * %GFP_NOFS will use direct reclaim but will not use any filesystem interfaces.
 * Please try to avoid using this flag directly and instead use
 * memalloc_nofs_{save,restore} to mark the whole scope which cannot/shouldn't
 * recurse into the FS layer with a short explanation why. All allocation
 * requests will inherit GFP_NOFS implicitly.
 *
 * %GFP_USER is for userspace allocations that also need to be directly
 * accessibly by the kernel or hardware. It is typically used by hardware
 * for buffers that are mapped to userspace (e.g. graphics) that hardware
 * still must DMA to. cpuset limits are enforced for these allocations.
 *
 * %GFP_DMA exists for historical reasons and should be avoided where possible.
 * The flags indicates that the caller requires that the lowest zone be
 * used (%ZONE_DMA or 16M on x86-64). Ideally, this would be removed but
 * it would require careful auditing as some users really require it and
 * others use the flag to avoid lowmem reserves in %ZONE_DMA and treat the
 * lowest zone as a type of emergency reserve.
 *
 * %GFP_DMA32 is similar to %GFP_DMA except that the caller requires a 32-bit
 * address.
 *
 * %GFP_HIGHUSER is for userspace allocations that may be mapped to userspace,
 * do not need to be directly accessible by the kernel but that cannot
 * move once in use. An example may be a hardware allocation that maps
 * data directly into userspace but has no addressing limitations.
 *
 * %GFP_HIGHUSER_MOVABLE is for userspace allocations that the kernel does not
 * need direct access to but can use kmap() when access is required. They
 * are expected to be movable via page reclaim or page migration. Typically,
 * pages on the LRU would also be allocated with %GFP_HIGHUSER_MOVABLE.
 *
 * %GFP_TRANSHUGE and %GFP_TRANSHUGE_LIGHT are used for THP allocations. They
 * are compound allocations that will generally fail quickly if memory is not
 * available and will not wake kswapd/kcompactd on failure. The _LIGHT
 * version does not attempt reclaim/compaction at all and is by default used
 * in page fault path, while the non-light is used by khugepaged.
 */
/*
 * IAMROOT, 2022.01.23:
 * - GFP_ATOMIC : irq handler에서 사용 가능 (no sleep)
 * - GFP_KERNEL = irq handler에서 사용 불가능 (sleep)
 * - 밑줄(_)이 없는 gfp flag는 2개이상의 기능을 담당한다.
 */
#define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_NOWAIT	(__GFP_KSWAPD_RECLAIM)

/*
 * IAMROOT, 2022.02.26: 
 * reclaim과 관련하여 
 * -GFP_NOIO: 회수시 io, fs를 사용하지 못하도록 한다.
 * -GFP_NOFS: 회수시 fs만을 사용하지 못하도록 한다.
 */
#define GFP_NOIO	(__GFP_RECLAIM)
#define GFP_NOFS	(__GFP_RECLAIM | __GFP_IO)
#define GFP_USER	(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_DMA		__GFP_DMA
#define GFP_DMA32	__GFP_DMA32
/*
 * IAMROOT, 2022.02.18:
 * - HIGHMEM + NORMAL
 */
#define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
/*
 * IAMROOT, 2022.02.18:
 * - MOVABLE + HIGHMEM + NORMAL
 */
#define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | \
			 __GFP_SKIP_KASAN_POISON)
#define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
#define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)

/* Convert GFP flags to their corresponding migrate type */
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_MOVABLE_SHIFT 3

/*
 * IAMROOT, 2022.02.26: 
 * 요청한 gfp 플래그로 migratetype을 결정하여 반환한다.
 * - __GFP_MOVABLE, __GFP_RECLAIMABLE 두 플래그를 사용하여 판단한다.
 * 
 * 예) GFP_KERNEL, GFP_ATOMIC
 *     -> migratetype과 관련한 플래그를 가지지 않는다.
 *        따라서 커널 메모리의 할당은 MIGRATE_UNMOVABLE로 선택된다.
 */
static inline int gfp_migratetype(const gfp_t gfp_flags)
{
	VM_WARN_ON((gfp_flags & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);
	BUILD_BUG_ON((1UL << GFP_MOVABLE_SHIFT) != ___GFP_MOVABLE);
	BUILD_BUG_ON((___GFP_MOVABLE >> GFP_MOVABLE_SHIFT) != MIGRATE_MOVABLE);

	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	/* Group based on mobility */
/*
 * IAMROOT, 2022.02.26: 
 * migratetype은 두 플래그만을 가지고 0~2까지 타입을 결정한다.
 * no flag:				-> MIGRATE_UNMOVABLE
 * __GFP_MOVABLE:			-> MIGRATE_MOVABLE
 * __GFP_RECLAIMABLE:			-> MIGRATE_RECLAIMABLE
 * __GFP_MOVABLE, __GFP_RECLAIMABLE	-> error!!!
 */
	return (gfp_flags & GFP_MOVABLE_MASK) >> GFP_MOVABLE_SHIFT;
}
#undef GFP_MOVABLE_MASK
#undef GFP_MOVABLE_SHIFT

static inline bool gfpflags_allow_blocking(const gfp_t gfp_flags)
{
	return !!(gfp_flags & __GFP_DIRECT_RECLAIM);
}

/**
 * gfpflags_normal_context - is gfp_flags a normal sleepable context?
 * @gfp_flags: gfp_flags to test
 *
 * Test whether @gfp_flags indicates that the allocation is from the
 * %current context and allowed to sleep.
 *
 * An allocation being allowed to block doesn't mean it owns the %current
 * context.  When direct reclaim path tries to allocate memory, the
 * allocation context is nested inside whatever %current was doing at the
 * time of the original allocation.  The nested allocation may be allowed
 * to block but modifying anything %current owns can corrupt the outer
 * context's expectations.
 *
 * %true result from this function indicates that the allocation context
 * can sleep and use anything that's associated with %current.
 */
static inline bool gfpflags_normal_context(const gfp_t gfp_flags)
{
	return (gfp_flags & (__GFP_DIRECT_RECLAIM | __GFP_MEMALLOC)) ==
		__GFP_DIRECT_RECLAIM;
}

#ifdef CONFIG_HIGHMEM
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#else
#define OPT_ZONE_HIGHMEM ZONE_NORMAL
#endif

#ifdef CONFIG_ZONE_DMA
#define OPT_ZONE_DMA ZONE_DMA
#else
#define OPT_ZONE_DMA ZONE_NORMAL
#endif

#ifdef CONFIG_ZONE_DMA32
#define OPT_ZONE_DMA32 ZONE_DMA32
#else
#define OPT_ZONE_DMA32 ZONE_NORMAL
#endif

/*
 * IAMROOT, 2022.02.18:
 * - GFP_ZONE_BAD macro로 bad처리를 한다.
 */
/*
 * GFP_ZONE_TABLE is a word size bitstring that is used for looking up the
 * zone to use given the lowest 4 bits of gfp_t. Entries are GFP_ZONES_SHIFT
 * bits long and there are 16 of them to cover all possible combinations of
 * __GFP_DMA, __GFP_DMA32, __GFP_MOVABLE and __GFP_HIGHMEM.
 *
 * The zone fallback order is MOVABLE=>HIGHMEM=>NORMAL=>DMA32=>DMA.
 * But GFP_MOVABLE is not only a zone specifier but also an allocation
 * policy. Therefore __GFP_MOVABLE plus another zone selector is valid.
 * Only 1 bit of the lowest 3 bits (DMA,DMA32,HIGHMEM) can be set to "1".
 *
 *       bit       result
 *       =================
 *       0x0    => NORMAL
 *       0x1    => DMA or NORMAL
 *       0x2    => HIGHMEM or NORMAL
 *       0x3    => BAD (DMA+HIGHMEM)
 *       0x4    => DMA32 or NORMAL
 *       0x5    => BAD (DMA+DMA32)
 *       0x6    => BAD (HIGHMEM+DMA32)
 *       0x7    => BAD (HIGHMEM+DMA32+DMA)
 *       0x8    => NORMAL (MOVABLE+0)
 *       0x9    => DMA or NORMAL (MOVABLE+DMA)
 *       0xa    => MOVABLE (Movable is valid only if HIGHMEM is set too)
 *       0xb    => BAD (MOVABLE+HIGHMEM+DMA)
 *       0xc    => DMA32 or NORMAL (MOVABLE+DMA32)
 *       0xd    => BAD (MOVABLE+DMA32+DMA)
 *       0xe    => BAD (MOVABLE+DMA32+HIGHMEM)
 *       0xf    => BAD (MOVABLE+DMA32+HIGHMEM+DMA)
 *
 * GFP_ZONES_SHIFT must be <= 2 on 32 bit platforms.
 */

/*
 * IAMROOT, 2022.02.12: 
 * - 32비트 시스템의 경우 최대 4개의 존 조합을 사용할 수 있다.
 * - 존 정보의 저장은 2비트를 사용하여 page 구조체의 플래그에 저장된다.
 */

#if defined(CONFIG_ZONE_DEVICE) && (MAX_NR_ZONES-1) <= 4
/* ZONE_DEVICE is not a valid GFP zone specifier */
#define GFP_ZONES_SHIFT 2
#else
#define GFP_ZONES_SHIFT ZONES_SHIFT
#endif

/*
 * IAMROOT, 2022.02.12: 
 * - 32비트 시스템의 경우 GFP_ZONES_SHIFT가 2를 초과하는 경우 에러
 * - 64비트 시스템의 경우 GFP_ZONES_SHIFT가 4를 초과하는 경우 에러
 *   (현재 존타입 수가 최대 6개 이므로 GFP_ZONES_SHIFT는 3비트를 사용한다)
 */
#if 16 * GFP_ZONES_SHIFT > BITS_PER_LONG
#error GFP_ZONES_SHIFT too large to create GFP_ZONE_TABLE integer
#endif

/*
 * IAMROOT, 2022.02.12: 
 * 존과 관련된 gfp 플래그를 사용해서 zone 타입을 알아내기 위해 사용하는 테이블
 * 예) DMA(0)+DMA32(1)+NORMAL(2)+MOVABLE(3)
 *     아래를 순서대로 숫자를 계산해보면
 *               2
 *     |         0
 *     |            (highmem 무시)
 *     |     0x100  (1 << 4 * 2)
 *     |   0x20000  (2 << 8 * 2)
 *     |         0
 *     |  0x300000  (3 << (8 | 2) * 2)
 *     | 0x1000000  (1 << (8 | 4) * 2)
 *   -----------------------------------
 *       0x1320102 
 *       위의 값중 하위 GFP_ZONES_SHIFT(2)비트 만큼만 사용하면 
 *      ->       2
 *
 * 다음과 같이 요청 시 찾은 존 타입:
 * - GFP_KERNEL: normal.
 * - GFP_DMA:    dma
 * - GFP_DMA32:  dma32
 *
 * ---
 *  유효한 gfp flag 조합은 정해져있다. 각각의 유효한 gfp flag들에 대해
 *  GFP_ZONES_SHIFT * gfp flags로 mask영역을 옮겨서 mask table을 만든다.
 *
 *  |               GFP_ZONE_TABLE bits                           ....
 *  | gfp flags1의 zone1| gfp flags2의 zone2| gfp flags3의 zone3|
 *  | 유효한 gfp flags1 | 유효한 gfp flags2 | 유효한 gfp flags3 | ..
 *  |<-GFP_ZONES_SHIFT->|<-GFP_ZONES_SHIFT->|<-GFP_ZONES_SHIFT-><..
 */
#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * GFP_ZONES_SHIFT)				       \
	| (OPT_ZONE_DMA << ___GFP_DMA * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_HIGHMEM << ___GFP_HIGHMEM * GFP_ZONES_SHIFT)	       \
	| (OPT_ZONE_DMA32 << ___GFP_DMA32 * GFP_ZONES_SHIFT)		       \
	| (ZONE_NORMAL << ___GFP_MOVABLE * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_DMA << (___GFP_MOVABLE | ___GFP_DMA) * GFP_ZONES_SHIFT)    \
	| (ZONE_MOVABLE << (___GFP_MOVABLE | ___GFP_HIGHMEM) * GFP_ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (___GFP_MOVABLE | ___GFP_DMA32) * GFP_ZONES_SHIFT)\
)

/*
 * GFP_ZONE_BAD is a bitmap for all combinations of __GFP_DMA, __GFP_DMA32
 * __GFP_HIGHMEM and __GFP_MOVABLE that are not permitted. One flag per
 * entry starting with bit 0. Bit is set if the combination is not
 * allowed.
 */
/*
 * IAMROOT, 2022.02.12: 
 * 적합하지 않은 존 구성을 알아내기 위해 사용한다. (빌드 경우)
 * - GFP_ZONES_SHIFT위 긴주석 참고
 * - 잘못된 gfp flags를 bit num으로 사용하여 해당 bit들을 set해놨다.
 *   후에 gfp flags가 잘못된지 검사를 할때에는 GFP_ZONE_BAD를 gfp flags만큼
 *   밀었을때 0번 bit가 1로 set되있다면 잘못된 gfp flag로 확인될것이다.
 */
#define GFP_ZONE_BAD ( \
	1 << (___GFP_DMA | ___GFP_HIGHMEM)				      \
	| 1 << (___GFP_DMA | ___GFP_DMA32)				      \
	| 1 << (___GFP_DMA32 | ___GFP_HIGHMEM)				      \
	| 1 << (___GFP_DMA | ___GFP_DMA32 | ___GFP_HIGHMEM)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_HIGHMEM | ___GFP_DMA)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_HIGHMEM)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA | ___GFP_HIGHMEM)  \
)

/*
 * IAMROOT, 2022.02.12: 
 *
 * - GFP_KERNEL등 GFP_ZONEMASK영역이 clear인 flag들: normal.
 * - GFP_DMA:    dma or normal
 * - GFP_DMA32:  dma32 or normal
 *
 * 존과 연관된 gfp 플래그를 사용하여 해당 존타입을 알아온다.
 * - GFP_ZONEMASK: dma, dma32, highmem, movable
 * - 위의 플래그가 지정되지 않은 경우 최상위 을 사용한다.
 * 
 * 반환되는 값은 존 타입이므로 0~5까지의 존 타입이 반환된다.
 */
static inline enum zone_type gfp_zone(gfp_t flags)
{
	enum zone_type z;
/*
 * IAMROOT, 2022.02.18:
 * - flags에서 zone bits를 추출 한다.
 */
	int bit = (__force int) (flags & GFP_ZONEMASK);

/*
 * IAMROOT, 2022.02.18:
 * - bit * GFP_ZONES_SHIFT에 bit에서 사용할수 있는 zone이 들어 있다. 해당
 *   zone을 추출한다.
 *
 * - ((1 << GFP_ZONES_SHIFT) - 1): 하위 3-bits 추출용
 */
	z = (GFP_ZONE_TABLE >> (bit * GFP_ZONES_SHIFT)) &
					 ((1 << GFP_ZONES_SHIFT) - 1);
	VM_BUG_ON((GFP_ZONE_BAD >> bit) & 1);
	return z;
}

/*
 * There is only one page-allocator function, and two main namespaces to
 * it. The alloc_page*() variants return 'struct page *' and as such
 * can allocate highmem pages, the *get*page*() variants return
 * virtual kernel addresses to the allocated page(s).
 */

/*
 * IAMROOT, 2022.02.12: 
 * - NUMA 커널에서 __GFP_THISNODE로 요청한 경우에만 ZONELIST_NOFALLBACK(1)을 
 * 선택하고 그 외의 경우 ZONELIST_FALLBACK(0)을 선택한다. 
 * - GFP_KERNEL은 __GFP_THISNODE와 관계없는 flag지만 명시적으로 그냥 사용한다.
 *   그래서 ZONELIST_FALLBACK를 가져올것이다.
 */
static inline int gfp_zonelist(gfp_t flags)
{
#ifdef CONFIG_NUMA
	if (unlikely(flags & __GFP_THISNODE))
		return ZONELIST_NOFALLBACK;
#endif
	return ZONELIST_FALLBACK;
}

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAX_NUMNODES*MAX_NR_ZONES zones.
 * There are two zonelists per node, one for all zones with memory and
 * one containing just zones from the node the zonelist belongs to.
 *
 * For the case of non-NUMA systems the NODE_DATA() gets optimized to
 * &contig_page_data at compile-time.
 */
/*
 * IAMROOT, 2022.02.12: 
 * NUMA 커널에서 __GFP_THISNODE로 요청한 경우에 따라 적절한 node_zonelists[]를 
 * 선택한다.
 * -> NODE->node_zonelists[0 or 1]을 선택한다.
 */
static inline struct zonelist *node_zonelist(int nid, gfp_t flags)
{
	return NODE_DATA(nid)->node_zonelists + gfp_zonelist(flags);
}

#ifndef HAVE_ARCH_FREE_PAGE
static inline void arch_free_page(struct page *page, int order) { }
#endif
#ifndef HAVE_ARCH_ALLOC_PAGE
static inline void arch_alloc_page(struct page *page, int order) { }
#endif
#ifndef HAVE_ARCH_MAKE_PAGE_ACCESSIBLE
static inline int arch_make_page_accessible(struct page *page)
{
	return 0;
}
#endif

struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
		nodemask_t *nodemask);

unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
				nodemask_t *nodemask, int nr_pages,
				struct list_head *page_list,
				struct page **page_array);

/* Bulk allocate order-0 pages */
static inline unsigned long
alloc_pages_bulk_list(gfp_t gfp, unsigned long nr_pages, struct list_head *list)
{
	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, list, NULL);
}

static inline unsigned long
alloc_pages_bulk_array(gfp_t gfp, unsigned long nr_pages, struct page **page_array)
{
	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, NULL, page_array);
}

/*
 * IAMROOT, 2022.07.02: 
 * 싱글 페이지들을 요청한 @nr_pages 만큼 할당하고, 
 * 할당받은 각각의 page 구조체를 출력 인자 @page_array에 대입하여 반환한다.
 * 할당받은 페이지 수를 반환한다.
 */
static inline unsigned long
alloc_pages_bulk_array_node(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
{
	if (nid == NUMA_NO_NODE)
		nid = numa_mem_id();

	return __alloc_pages_bulk(gfp, nid, NULL, nr_pages, NULL, page_array);
}

/*
 * Allocate pages, preferring the node given as nid. The node must be valid and
 * online. For more general interface, see alloc_pages_node().
 */
static inline struct page *
__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
	VM_WARN_ON((gfp_mask & __GFP_THISNODE) && !node_online(nid));

	return __alloc_pages(gfp_mask, order, nid, NULL);
}

/*
 * Allocate pages, preferring the node given as nid. When nid == NUMA_NO_NODE,
 * prefer the current CPU's closest node. Otherwise node must be valid and
 * online.
 */

/*
 * IAMROOT, 2022.02.05:
 * - TODO
 *   nid node에서 order page만큼 할당받아서 그것을 관리하는 page pointer를
 *   반환한다.
 */
static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
						unsigned int order)
{
	if (nid == NUMA_NO_NODE)
		nid = numa_mem_id();

	return __alloc_pages_node(nid, gfp_mask, order);
}

#ifdef CONFIG_NUMA
struct page *alloc_pages(gfp_t gfp, unsigned int order);
extern struct page *alloc_pages_vma(gfp_t gfp_mask, int order,
			struct vm_area_struct *vma, unsigned long addr,
			int node, bool hugepage);
#define alloc_hugepage_vma(gfp_mask, vma, addr, order) \
	alloc_pages_vma(gfp_mask, order, vma, addr, numa_node_id(), true)
#else
static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	return alloc_pages_node(numa_node_id(), gfp_mask, order);
}
#define alloc_pages_vma(gfp_mask, order, vma, addr, node, false)\
	alloc_pages(gfp_mask, order)
#define alloc_hugepage_vma(gfp_mask, vma, addr, order) \
	alloc_pages(gfp_mask, order)
#endif
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

/*
 * IAMROOT, 2022.05.14:
 * - gfp_mask : GFP_HIGHUSER_MOVABLE
 *   user app용 vma에 mapping되있는 anon memory alloc.(do_cow_fault() 참고)
 */
#define alloc_page_vma(gfp_mask, vma, addr)			\
	alloc_pages_vma(gfp_mask, 0, vma, addr, numa_node_id(), false)

extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
extern unsigned long get_zeroed_page(gfp_t gfp_mask);

void *alloc_pages_exact(size_t size, gfp_t gfp_mask);
void free_pages_exact(void *virt, size_t size);
void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask);

#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)

#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA, (order))

extern void __free_pages(struct page *page, unsigned int order);
extern void free_pages(unsigned long addr, unsigned int order);

struct page_frag_cache;
extern void __page_frag_cache_drain(struct page *page, unsigned int count);
extern void *page_frag_alloc_align(struct page_frag_cache *nc,
				   unsigned int fragsz, gfp_t gfp_mask,
				   unsigned int align_mask);

static inline void *page_frag_alloc(struct page_frag_cache *nc,
			     unsigned int fragsz, gfp_t gfp_mask)
{
	return page_frag_alloc_align(nc, fragsz, gfp_mask, ~0u);
}

extern void page_frag_free(void *addr);

#define __free_page(page) __free_pages((page), 0)

/*
 * IAMROOT, 2022.05.14:
 * - order 0로 free_pages 수행
 */
#define free_page(addr) free_pages((addr), 0)

void page_alloc_init(void);
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp);
void drain_all_pages(struct zone *zone);
void drain_local_pages(struct zone *zone);

void page_alloc_init_late(void);

/*
 * gfp_allowed_mask is set to GFP_BOOT_MASK during early boot to restrict what
 * GFP flags are used before interrupts are enabled. Once interrupts are
 * enabled, it is set to __GFP_BITS_MASK while the system is running. During
 * hibernation, it is used by PM to avoid I/O during memory allocation while
 * devices are suspended.
 */
extern gfp_t gfp_allowed_mask;

/* Returns true if the gfp_mask allows use of ALLOC_NO_WATERMARK */
bool gfp_pfmemalloc_allowed(gfp_t gfp_mask);

extern void pm_restrict_gfp_mask(void);
extern void pm_restore_gfp_mask(void);

extern gfp_t vma_thp_gfp_mask(struct vm_area_struct *vma);

#ifdef CONFIG_PM_SLEEP
extern bool pm_suspended_storage(void);
#else
static inline bool pm_suspended_storage(void)
{
	return false;
}
#endif /* CONFIG_PM_SLEEP */

#ifdef CONFIG_CONTIG_ALLOC
/* The below functions must be run on a range from a single zone. */
extern int alloc_contig_range(unsigned long start, unsigned long end,
			      unsigned migratetype, gfp_t gfp_mask);
extern struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
				       int nid, nodemask_t *nodemask);
#endif
void free_contig_range(unsigned long pfn, unsigned long nr_pages);

#ifdef CONFIG_CMA
/* CMA stuff */
extern void init_cma_reserved_pageblock(struct page *page);
#endif

#endif /* __LINUX_GFP_H */
