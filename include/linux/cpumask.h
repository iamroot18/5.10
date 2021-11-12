/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_CPUMASK_H
#define __LINUX_CPUMASK_H

/*
 * Cpumasks provide a bitmap suitable for representing the
 * set of CPU's in a system, one bit position per CPU number.  In general,
 * only nr_cpu_ids (<= NR_CPUS) bits are valid.
 */
#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>
#include <linux/atomic.h>
#include <linux/bug.h>

/* IAMROOT, 2021.09.30:
 * CONFIG_NR_CPUS에 따라 compile 시점에 cpumask 크기가 정해짐이 보인다.
 */
/* Don't assign or return these: may not be this big! */
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

/**
 * cpumask_bits - get the bits in a cpumask
 * @maskp: the struct cpumask *
 *
 * You should only assume nr_cpu_ids bits of this mask are valid.  This is
 * a macro so it's const-correct.
 */
#define cpumask_bits(maskp) ((maskp)->bits)

/**
 * cpumask_pr_args - printf args to output a cpumask
 * @maskp: cpumask to be printed
 *
 * Can be used to provide arguments for '%*pb[l]' when printing a cpumask.
 */
#define cpumask_pr_args(maskp)		nr_cpu_ids, cpumask_bits(maskp)

/* IAMROOT, 2021.09.30:
 * NR_CPUS 는 compile time에 정해지고, nr_cpu_ids는 runtime에 정해진다.
 * NR_CPUS: 최대 cpu 장착 개수.
 * nr_cpu_ids: 실제 cpu 장착 개수.
 */
#if NR_CPUS == 1
#define nr_cpu_ids		1U
#else
extern unsigned int nr_cpu_ids;
#endif

/* IAMROOT, 2021.09.30:
 * cpumask를 stack을 쓰지 않고 alloc하여 사용한다는 의미이다. cpu가 많아지면
 * copy보다는 pointer로 넘겨주는게 효율이 좋기때문이다.
 * (cpumask_var_t 참고)
 *
 * 따라서 별도의 다이나믹 할당 관리가 필요하다.
 * 이 옵션은 cpu가 long 타입 비트수(32 or 64)를 초과하는 경우 사용해야 효과적이다.
 */
#ifdef CONFIG_CPUMASK_OFFSTACK
/* Assuming NR_CPUS is huge, a runtime limit is more efficient.  Also,
 * not all bits may be allocated. */
#define nr_cpumask_bits	nr_cpu_ids
#else
#define nr_cpumask_bits	((unsigned int)NR_CPUS)
#endif

/*
 * The following particular system cpumasks and operations manage
 * possible, present, active and online cpus.
 *
 *     cpu_possible_mask- has bit 'cpu' set iff cpu is populatable
 *     cpu_present_mask - has bit 'cpu' set iff cpu is populated
 *     cpu_online_mask  - has bit 'cpu' set iff cpu available to scheduler
 *     cpu_active_mask  - has bit 'cpu' set iff cpu available to migration
 *
 *  If !CONFIG_HOTPLUG_CPU, present == possible, and active == online.
 *
 *  The cpu_possible_mask is fixed at boot time, as the set of CPU id's
 *  that it is possible might ever be plugged in at anytime during the
 *  life of that system boot.  The cpu_present_mask is dynamic(*),
 *  representing which CPUs are currently plugged in.  And
 *  cpu_online_mask is the dynamic subset of cpu_present_mask,
 *  indicating those CPUs available for scheduling.
 *
 *  If HOTPLUG is enabled, then cpu_possible_mask is forced to have
 *  all NR_CPUS bits set, otherwise it is just the set of CPUs that
 *  ACPI reports present at boot.
 *
 *  If HOTPLUG is enabled, then cpu_present_mask varies dynamically,
 *  depending on what ACPI reports as currently plugged in, otherwise
 *  cpu_present_mask is just a copy of cpu_possible_mask.
 *
 *  (*) Well, cpu_present_mask is dynamic in the hotplug case.  If not
 *      hotplug, it's a copy of cpu_possible_mask, hence fixed at boot.
 *
 * Subtleties:
 * 1) UP arch's (NR_CPUS == 1, CONFIG_SMP not defined) hardcode
 *    assumption that their single CPU is online.  The UP
 *    cpu_{online,possible,present}_masks are placebos.  Changing them
 *    will have no useful affect on the following num_*_cpus()
 *    and cpu_*() macros in the UP case.  This ugliness is a UP
 *    optimization - don't waste any instructions or memory references
 *    asking if you're online or how many CPUs there are if there is
 *    only one CPU.
 */

/*
 * IAMROOT, 2021.11.09:
 * - possible: NR_CPUS 내에서 최대 장착 가능한 cpu
 * - present: CPU를 인식하여 동작한 상태. (hot-plug로 장착/탈착 가능)
 * - online: 테스크가 동작 가능한 상태
 * - active: 테스크 스케줄링이 가능한 상태
 */
extern struct cpumask __cpu_possible_mask;
extern struct cpumask __cpu_online_mask;
extern struct cpumask __cpu_present_mask;
extern struct cpumask __cpu_active_mask;
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)

extern atomic_t __num_online_cpus;

#if NR_CPUS > 1
/**
 * num_online_cpus() - Read the number of online CPUs
 *
 * Despite the fact that __num_online_cpus is of type atomic_t, this
 * interface gives only a momentary snapshot and is not protected against
 * concurrent CPU hotplug operations unless invoked from a cpuhp_lock held
 * region.
 */
static inline unsigned int num_online_cpus(void)
{
	return atomic_read(&__num_online_cpus);
}
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
#define num_present_cpus()	cpumask_weight(cpu_present_mask)
#define num_active_cpus()	cpumask_weight(cpu_active_mask)
#define cpu_online(cpu)		cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_possible(cpu)	cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
#define cpu_active(cpu)		cpumask_test_cpu((cpu), cpu_active_mask)
#else
/* IAMROOT, 2021.11.12: NR_CPU == 1 */
#define num_online_cpus()	1U
#define num_possible_cpus()	1U
#define num_present_cpus()	1U
#define num_active_cpus()	1U
#define cpu_online(cpu)		((cpu) == 0)
#define cpu_possible(cpu)	((cpu) == 0)
#define cpu_present(cpu)	((cpu) == 0)
#define cpu_active(cpu)		((cpu) == 0)
#endif

extern cpumask_t cpus_booted_once_mask;

static inline void cpu_max_bits_warn(unsigned int cpu, unsigned int bits)
{
#ifdef CONFIG_DEBUG_PER_CPU_MAPS
	WARN_ON_ONCE(cpu >= bits);
#endif /* CONFIG_DEBUG_PER_CPU_MAPS */
}

/*
 * IAMROOT, 2021.11.09:
 * nr_cpumask_bits보다 cpu번호가 크거나 같은지 check한다.
 */
/* verify cpu argument to cpumask_* operators */
static inline unsigned int cpumask_check(unsigned int cpu)
{
	cpu_max_bits_warn(cpu, nr_cpumask_bits);
	return cpu;
}

#if NR_CPUS == 1
/* Uniprocessor.  Assume all masks are "1". */
static inline unsigned int cpumask_first(const struct cpumask *srcp)
{
	return 0;
}

static inline unsigned int cpumask_last(const struct cpumask *srcp)
{
	return 0;
}

/* Valid inputs for n are -1 and 0. */
static inline unsigned int cpumask_next(int n, const struct cpumask *srcp)
{
	return n+1;
}

static inline unsigned int cpumask_next_zero(int n, const struct cpumask *srcp)
{
	return n+1;
}

static inline unsigned int cpumask_next_and(int n,
					    const struct cpumask *srcp,
					    const struct cpumask *andp)
{
	return n+1;
}

static inline unsigned int cpumask_next_wrap(int n, const struct cpumask *mask,
					     int start, bool wrap)
{
	/* cpu0 unless stop condition, wrap and at cpu0, then nr_cpumask_bits */
	return (wrap && n == 0);
}

/* cpu must be a valid cpu, ie 0, so there's no other choice. */
static inline unsigned int cpumask_any_but(const struct cpumask *mask,
					   unsigned int cpu)
{
	return 1;
}

static inline unsigned int cpumask_local_spread(unsigned int i, int node)
{
	return 0;
}

static inline int cpumask_any_and_distribute(const struct cpumask *src1p,
					     const struct cpumask *src2p) {
	return cpumask_next_and(-1, src1p, src2p);
}

#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_not(cpu, mask)		\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_wrap(cpu, mask, start)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)(start))
#define for_each_cpu_and(cpu, mask1, mask2)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask1, (void)mask2)
#else
/* IAMROOT, 2021.11.12: NR_CPUS > 1 */
/**
 * cpumask_first - get the first cpu in a cpumask
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
static inline unsigned int cpumask_first(const struct cpumask *srcp)
{
	return find_first_bit(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_last - get the last CPU in a cpumask
 * @srcp:	- the cpumask pointer
 *
 * Returns	>= nr_cpumask_bits if no CPUs set.
 */
static inline unsigned int cpumask_last(const struct cpumask *srcp)
{
	return find_last_bit(cpumask_bits(srcp), nr_cpumask_bits);
}

unsigned int cpumask_next(int n, const struct cpumask *srcp);

/**
 * cpumask_next_zero - get the next unset cpu in a cpumask
 * @n: the cpu prior to the place to search (ie. return will be > @n)
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no further cpus unset.
 */
static inline unsigned int cpumask_next_zero(int n, const struct cpumask *srcp)
{
	/* -1 is a legal arg here. */
	if (n != -1)
		cpumask_check(n);
	return find_next_zero_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

int cpumask_next_and(int n, const struct cpumask *, const struct cpumask *);
int cpumask_any_but(const struct cpumask *mask, unsigned int cpu);
unsigned int cpumask_local_spread(unsigned int i, int node);
int cpumask_any_and_distribute(const struct cpumask *src1p,
			       const struct cpumask *src2p);

/**
 * for_each_cpu - iterate over every cpu in a mask
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask pointer
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu(cpu, mask)				\
	for ((cpu) = -1;				\
		(cpu) = cpumask_next((cpu), (mask)),	\
		(cpu) < nr_cpu_ids;)

/**
 * for_each_cpu_not - iterate over every cpu in a complemented mask
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask pointer
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu_not(cpu, mask)				\
	for ((cpu) = -1;					\
		(cpu) = cpumask_next_zero((cpu), (mask)),	\
		(cpu) < nr_cpu_ids;)

extern int cpumask_next_wrap(int n, const struct cpumask *mask, int start, bool wrap);

/**
 * for_each_cpu_wrap - iterate over every cpu in a mask, starting at a specified location
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask poiter
 * @start: the start location
 *
 * The implementation does not assume any bit in @mask is set (including @start).
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu_wrap(cpu, mask, start)					\
	for ((cpu) = cpumask_next_wrap((start)-1, (mask), (start), false);	\
	     (cpu) < nr_cpumask_bits;						\
	     (cpu) = cpumask_next_wrap((cpu), (mask), (start), true))

/**
 * for_each_cpu_and - iterate over every cpu in both masks
 * @cpu: the (optionally unsigned) integer iterator
 * @mask1: the first cpumask pointer
 * @mask2: the second cpumask pointer
 *
 * This saves a temporary CPU mask in many places.  It is equivalent to:
 *	struct cpumask tmp;
 *	cpumask_and(&tmp, &mask1, &mask2);
 *	for_each_cpu(cpu, &tmp)
 *		...
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu_and(cpu, mask1, mask2)				\
	for ((cpu) = -1;						\
		(cpu) = cpumask_next_and((cpu), (mask1), (mask2)),	\
		(cpu) < nr_cpu_ids;)
#endif /* SMP */

#define CPU_BITS_NONE						\
{								\
	[0 ... BITS_TO_LONGS(NR_CPUS)-1] = 0UL			\
}

#define CPU_BITS_CPU0						\
{								\
	[0] =  1UL						\
}

/**
 * cpumask_set_cpu - set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static inline void __cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	__set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}


/**
 * cpumask_clear_cpu - clear a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static inline void __cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	__clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

/**
 * cpumask_test_cpu - test for a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in @cpumask, else returns 0
 */
static inline int cpumask_test_cpu(int cpu, const struct cpumask *cpumask)
{
	return test_bit(cpumask_check(cpu), cpumask_bits((cpumask)));
}

/**
 * cpumask_test_and_set_cpu - atomically test and set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in old bitmap of @cpumask, else returns 0
 *
 * test_and_set_bit wrapper for cpumasks.
 */
static inline int cpumask_test_and_set_cpu(int cpu, struct cpumask *cpumask)
{
	return test_and_set_bit(cpumask_check(cpu), cpumask_bits(cpumask));
}

/**
 * cpumask_test_and_clear_cpu - atomically test and clear a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in old bitmap of @cpumask, else returns 0
 *
 * test_and_clear_bit wrapper for cpumasks.
 */
static inline int cpumask_test_and_clear_cpu(int cpu, struct cpumask *cpumask)
{
	return test_and_clear_bit(cpumask_check(cpu), cpumask_bits(cpumask));
}

/**
 * cpumask_setall - set all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_setall(struct cpumask *dstp)
{
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_clear - clear all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_clear(struct cpumask *dstp)
{
	bitmap_zero(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_and - *dstp = *src1p & *src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 *
 * If *@dstp is empty, returns 0, else returns 1
 */
static inline int cpumask_and(struct cpumask *dstp,
			       const struct cpumask *src1p,
			       const struct cpumask *src2p)
{
	return bitmap_and(cpumask_bits(dstp), cpumask_bits(src1p),
				       cpumask_bits(src2p), nr_cpumask_bits);
}

/**
 * cpumask_or - *dstp = *src1p | *src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 */
static inline void cpumask_or(struct cpumask *dstp, const struct cpumask *src1p,
			      const struct cpumask *src2p)
{
	bitmap_or(cpumask_bits(dstp), cpumask_bits(src1p),
				      cpumask_bits(src2p), nr_cpumask_bits);
}

/**
 * cpumask_xor - *dstp = *src1p ^ *src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 */
static inline void cpumask_xor(struct cpumask *dstp,
			       const struct cpumask *src1p,
			       const struct cpumask *src2p)
{
	bitmap_xor(cpumask_bits(dstp), cpumask_bits(src1p),
				       cpumask_bits(src2p), nr_cpumask_bits);
}

/**
 * cpumask_andnot - *dstp = *src1p & ~*src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 *
 * If *@dstp is empty, returns 0, else returns 1
 */
static inline int cpumask_andnot(struct cpumask *dstp,
				  const struct cpumask *src1p,
				  const struct cpumask *src2p)
{
	return bitmap_andnot(cpumask_bits(dstp), cpumask_bits(src1p),
					  cpumask_bits(src2p), nr_cpumask_bits);
}

/**
 * cpumask_complement - *dstp = ~*srcp
 * @dstp: the cpumask result
 * @srcp: the input to invert
 */
static inline void cpumask_complement(struct cpumask *dstp,
				      const struct cpumask *srcp)
{
	bitmap_complement(cpumask_bits(dstp), cpumask_bits(srcp),
					      nr_cpumask_bits);
}

/**
 * cpumask_equal - *src1p == *src2p
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool cpumask_equal(const struct cpumask *src1p,
				const struct cpumask *src2p)
{
	return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p),
						 nr_cpumask_bits);
}

/**
 * cpumask_or_equal - *src1p | *src2p == *src3p
 * @src1p: the first input
 * @src2p: the second input
 * @src3p: the third input
 */
static inline bool cpumask_or_equal(const struct cpumask *src1p,
				    const struct cpumask *src2p,
				    const struct cpumask *src3p)
{
	return bitmap_or_equal(cpumask_bits(src1p), cpumask_bits(src2p),
			       cpumask_bits(src3p), nr_cpumask_bits);
}

/**
 * cpumask_intersects - (*src1p & *src2p) != 0
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool cpumask_intersects(const struct cpumask *src1p,
				     const struct cpumask *src2p)
{
	return bitmap_intersects(cpumask_bits(src1p), cpumask_bits(src2p),
						      nr_cpumask_bits);
}

/**
 * cpumask_subset - (*src1p & ~*src2p) == 0
 * @src1p: the first input
 * @src2p: the second input
 *
 * Returns 1 if *@src1p is a subset of *@src2p, else returns 0
 */
static inline int cpumask_subset(const struct cpumask *src1p,
				 const struct cpumask *src2p)
{
	return bitmap_subset(cpumask_bits(src1p), cpumask_bits(src2p),
						  nr_cpumask_bits);
}

/**
 * cpumask_empty - *srcp == 0
 * @srcp: the cpumask to that all cpus < nr_cpu_ids are clear.
 */
static inline bool cpumask_empty(const struct cpumask *srcp)
{
	return bitmap_empty(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_full - *srcp == 0xFFFFFFFF...
 * @srcp: the cpumask to that all cpus < nr_cpu_ids are set.
 */
static inline bool cpumask_full(const struct cpumask *srcp)
{
	return bitmap_full(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_weight - Count of bits in *srcp
 * @srcp: the cpumask to count bits (< nr_cpu_ids) in.
 */
static inline unsigned int cpumask_weight(const struct cpumask *srcp)
{
	return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_shift_right - *dstp = *srcp >> n
 * @dstp: the cpumask result
 * @srcp: the input to shift
 * @n: the number of bits to shift by
 */
static inline void cpumask_shift_right(struct cpumask *dstp,
				       const struct cpumask *srcp, int n)
{
	bitmap_shift_right(cpumask_bits(dstp), cpumask_bits(srcp), n,
					       nr_cpumask_bits);
}

/**
 * cpumask_shift_left - *dstp = *srcp << n
 * @dstp: the cpumask result
 * @srcp: the input to shift
 * @n: the number of bits to shift by
 */
static inline void cpumask_shift_left(struct cpumask *dstp,
				      const struct cpumask *srcp, int n)
{
	bitmap_shift_left(cpumask_bits(dstp), cpumask_bits(srcp), n,
					      nr_cpumask_bits);
}

/**
 * cpumask_copy - *dstp = *srcp
 * @dstp: the result
 * @srcp: the input cpumask
 */
static inline void cpumask_copy(struct cpumask *dstp,
				const struct cpumask *srcp)
{
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_any - pick a "random" cpu from *srcp
 * @srcp: the input cpumask
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
#define cpumask_any(srcp) cpumask_first(srcp)

/**
 * cpumask_first_and - return the first cpu from *srcp1 & *srcp2
 * @src1p: the first input
 * @src2p: the second input
 *
 * Returns >= nr_cpu_ids if no cpus set in both.  See also cpumask_next_and().
 */
#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))

/**
 * cpumask_any_and - pick a "random" cpu from *mask1 & *mask2
 * @mask1: the first input cpumask
 * @mask2: the second input cpumask
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))

/**
 * cpumask_of - the cpumask containing just a given cpu
 * @cpu: the cpu (<= nr_cpu_ids)
 */
#define cpumask_of(cpu) (get_cpu_mask(cpu))

/**
 * cpumask_parse_user - extract a cpumask from a user string
 * @buf: the buffer to extract from
 * @len: the length of the buffer
 * @dstp: the cpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int cpumask_parse_user(const char __user *buf, int len,
				     struct cpumask *dstp)
{
	return bitmap_parse_user(buf, len, cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_parselist_user - extract a cpumask from a user string
 * @buf: the buffer to extract from
 * @len: the length of the buffer
 * @dstp: the cpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int cpumask_parselist_user(const char __user *buf, int len,
				     struct cpumask *dstp)
{
	return bitmap_parselist_user(buf, len, cpumask_bits(dstp),
				     nr_cpumask_bits);
}

/**
 * cpumask_parse - extract a cpumask from a string
 * @buf: the buffer to extract from
 * @dstp: the cpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int cpumask_parse(const char *buf, struct cpumask *dstp)
{
	return bitmap_parse(buf, UINT_MAX, cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpulist_parse - extract a cpumask from a user string of ranges
 * @buf: the buffer to extract from
 * @dstp: the cpumask to set.
 *
 * Returns -errno, or 0 for success.
 */
static inline int cpulist_parse(const char *buf, struct cpumask *dstp)
{
	return bitmap_parselist(buf, cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_size - size to allocate for a 'struct cpumask' in bytes
 */
static inline unsigned int cpumask_size(void)
{
	return BITS_TO_LONGS(nr_cpumask_bits) * sizeof(long);
}

/*
 * cpumask_var_t: struct cpumask for stack usage.
 *
 * Oh, the wicked games we play!  In order to make kernel coding a
 * little more difficult, we typedef cpumask_var_t to an array or a
 * pointer: doing &mask on an array is a noop, so it still works.
 *
 * ie.
 *	cpumask_var_t tmpmask;
 *	if (!alloc_cpumask_var(&tmpmask, GFP_KERNEL))
 *		return -ENOMEM;
 *
 *	  ... use 'tmpmask' like a normal struct cpumask * ...
 *
 *	free_cpumask_var(tmpmask);
 *
 *
 * However, one notable exception is there. alloc_cpumask_var() allocates
 * only nr_cpumask_bits bits (in the other hand, real cpumask_t always has
 * NR_CPUS bits). Therefore you don't have to dereference cpumask_var_t.
 *
 *	cpumask_var_t tmpmask;
 *	if (!alloc_cpumask_var(&tmpmask, GFP_KERNEL))
 *		return -ENOMEM;
 *
 *	var = *tmpmask;
 *
 * This code makes NR_CPUS length memcopy and brings to a memory corruption.
 * cpumask_copy() provide safe copy functionality.
 *
 * Note that there is another evil here: If you define a cpumask_var_t
 * as a percpu variable then the way to obtain the address of the cpumask
 * structure differently influences what this_cpu_* operation needs to be
 * used. Please use this_cpu_cpumask_var_t in those cases. The direct use
 * of this_cpu_ptr() or this_cpu_read() will lead to failures when the
 * other type of cpumask_var_t implementation is configured.
 *
 * Please also note that __cpumask_var_read_mostly can be used to declare
 * a cpumask_var_t variable itself (not its content) as read mostly.
 */
#ifdef CONFIG_CPUMASK_OFFSTACK

/* IAMROOT, 2021.09.30:
 * 동적할당을 하는것이 보인다. alloc 및 free함수가 존재한다.
 */
typedef struct cpumask *cpumask_var_t;

#define this_cpu_cpumask_var_ptr(x)	this_cpu_read(x)
#define __cpumask_var_read_mostly	__read_mostly

bool alloc_cpumask_var_node(cpumask_var_t *mask, gfp_t flags, int node);
bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags);
bool zalloc_cpumask_var_node(cpumask_var_t *mask, gfp_t flags, int node);
bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags);
void alloc_bootmem_cpumask_var(cpumask_var_t *mask);
void free_cpumask_var(cpumask_var_t mask);
void free_bootmem_cpumask_var(cpumask_var_t mask);

static inline bool cpumask_available(cpumask_var_t mask)
{
	return mask != NULL;
}

#else
/* IAMROOT, 2021.09.30:
 * 정적할당을 하는것이 보인다. alloc 및 free함수가 실제 code가 없는것이 보인다.
 */
typedef struct cpumask cpumask_var_t[1];

#define this_cpu_cpumask_var_ptr(x) this_cpu_ptr(x)
#define __cpumask_var_read_mostly

static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return true;
}

static inline bool alloc_cpumask_var_node(cpumask_var_t *mask, gfp_t flags,
					  int node)
{
	return true;
}

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	cpumask_clear(*mask);
	return true;
}

static inline bool zalloc_cpumask_var_node(cpumask_var_t *mask, gfp_t flags,
					  int node)
{
	cpumask_clear(*mask);
	return true;
}

static inline void alloc_bootmem_cpumask_var(cpumask_var_t *mask)
{
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline void free_bootmem_cpumask_var(cpumask_var_t mask)
{
}

static inline bool cpumask_available(cpumask_var_t mask)
{
	return true;
}
#endif /* CONFIG_CPUMASK_OFFSTACK */

/* It's common to want to use cpu_all_mask in struct member initializers,
 * so it has to refer to an address rather than a pointer. */
extern const DECLARE_BITMAP(cpu_all_bits, NR_CPUS);
/*
 * IAMROOT, 2021.11.13:
 * cpu_all_bits(=CPU_BITS_ALL)를 cpumask_t로 감싼 것.
 */
#define cpu_all_mask to_cpumask(cpu_all_bits)

/*
 * IAMROOT, 2021.11.13:
 * cpu_bit_bitmap[0](=0)를 cpumask_t로 감싼 것.
 */
/* First bits of cpu_bit_bitmap are in fact unset. */
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])

#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)

/* Wrappers for arch boot code to manipulate normally-constant masks */
void init_cpu_present(const struct cpumask *src);
void init_cpu_possible(const struct cpumask *src);
void init_cpu_online(const struct cpumask *src);

/*
 * IAMROOT, 2021.11.13:
 * __cpu_possible_mask의 bitmap을 0으로 clear.
 */
static inline void reset_cpu_possible_mask(void)
{
	bitmap_zero(cpumask_bits(&__cpu_possible_mask), NR_CPUS);
}

/*
 * IAMROOT, 2021.11.13:
 * - possible이 true이면
 *   __cpu_possible_mask의 bitmap에서 해당 cpu를 set.
 *
 * - possible이 false이면
 *   __cpu_possible_mask의 bitmap에서 해당 cpu를 claer.
 */
static inline void
set_cpu_possible(unsigned int cpu, bool possible)
{
	if (possible)
		cpumask_set_cpu(cpu, &__cpu_possible_mask);
	else
		cpumask_clear_cpu(cpu, &__cpu_possible_mask);
}

/*
 * IAMROOT, 2021.11.13:
 * - present가 true이면
 *   __cpu_present_mask의 bitmap에서 해당 cpu를 set.
 *
 * - present가 false이면
 *   __cpu_present_mask의 bitmap에서 해당 cpu를 claer.
 */
static inline void
set_cpu_present(unsigned int cpu, bool present)
{
	if (present)
		cpumask_set_cpu(cpu, &__cpu_present_mask);
	else
		cpumask_clear_cpu(cpu, &__cpu_present_mask);
}

void set_cpu_online(unsigned int cpu, bool online);

/*
 * IAMROOT, 2021.11.13:
 * - active가 true이면
 *   __cpu_active_mask의 bitmap에서 해당 cpu를 set.
 *
 * - active가 false이면
 *   __cpu_active_mask의 bitmap에서 해당 cpu를 claer.
 */
static inline void
set_cpu_active(unsigned int cpu, bool active)
{
	if (active)
		cpumask_set_cpu(cpu, &__cpu_active_mask);
	else
		cpumask_clear_cpu(cpu, &__cpu_active_mask);
}


/*
 * IAMROOT, 2021.11.13:
 * - ternary operator를 잘 보면 항상 true여서
 *   false인 case의 (void *)sizeof(__check_is_bitmap(bitmap))
 *   이 왜 필요지 의문이 들 수 있다. 그 이유는, compile-time에
 *   bitmap이 정말 unsigned long * 타입이 맞는지 확인하기
 *   위해서이다. 해당 타입이 아니라면 compilation warning이
 *   발생할 것이다.
 *   https://zhuanlan.zhihu.com/p/163850501
 */
/**
 * to_cpumask - convert an NR_CPUS bitmap to a struct cpumask *
 * @bitmap: the bitmap
 *
 * There are a few places where cpumask_var_t isn't appropriate and
 * static cpumasks must be used (eg. very early boot), yet we don't
 * expose the definition of 'struct cpumask'.
 *
 * This does the conversion, and can be used as a constant initializer.
 */
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))

/*
 * IAMROOT, 2021.11.13:
 * - compilep-time에 bitmap이 unsigned long * 타입인지
 *   확인하기 위한 용도.
 */
static inline int __check_is_bitmap(const unsigned long *bitmap)
{
	return 1;
}

/*
 * IAMROOT, 2021.11.13:
 * - Second dimension의 크기인 BITS_TO_LONGS(NR_CPUS)가
 *   cpumask_t의 bitmap 크기와 같다는 점에 주목.
 *
 * - cpu_bit_bitmap:
 *   [0][0] = 0, [1][0] = 1, [2][0] = 2,
 *   [3][0] = 4, [4][0] = 8, [5][0] = 16,
 *   ...
 */
/*
 * Special-case data structure for "single bit set only" constant CPU masks.
 *
 * We pre-generate all the 64 (or 32) possible bit positions, with enough
 * padding to the left and the right, and return the constant pointer
 * appropriately offset.
 */
extern const unsigned long
	cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)];

/*
 * IAMROOT, 2021.11.13:
 * - ex) NR_CPUS가 128이라고 가정해 보자.
 *
 *   cpu_bit_bitmap:
 *     [0][0]  = (0),     [0][1]  = 0,
 *     [1][0]  = (1<<0),  [1][1]  = 0,
 *     [2][0]  = (2<<0),  [2][1]  = 0,
 *     [3][0]  = (4<<0),  [3][1]  = 0,
 *     ...
 *     [64][0] = (1<<63), [64][1] = 0,
 *
 *   get_cpu_mask(0)   = {(1<<0), 0}
 *   get_cpu_mask(1)   = {(1<<1), 0}
 *   ...
 *   get_cpu_mask(63)  = {(1<<63), 0}
 *
 *   get_cpu_mask(64)  = {0, (1<<0)}
 *   get_cpu_mask(65)  = {0, (1<<1)}
 *   ...
 *   get_cpu_mask(127) = {0, (1<<63)}
 *
 *   아래의 링크의 그림을 참조하면 이해하는데 도움이 된다.
 *   https://zhuanlan.zhihu.com/p/163850501
 */
static inline const struct cpumask *get_cpu_mask(unsigned int cpu)
{
	const unsigned long *p = cpu_bit_bitmap[1 + cpu % BITS_PER_LONG];
	p -= cpu / BITS_PER_LONG;
	return to_cpumask(p);
}

#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))

/*
 * IAMROOT, 2021.11.09:
 * - CPU_BITS_ALL
 *   ex) NR_CPUS = 64 + 64 + 32
 *       CPU_BITS_ALL = 0xffff_ffff_ffff_ffff
 *                      0xffff_ffff_ffff_ffff
 *                      0x0000_0000_ffff_ffff
 */
#if NR_CPUS <= BITS_PER_LONG
#define CPU_BITS_ALL						\
{								\
	[BITS_TO_LONGS(NR_CPUS)-1] = BITMAP_LAST_WORD_MASK(NR_CPUS)	\
}

#else /* NR_CPUS > BITS_PER_LONG */

#define CPU_BITS_ALL						\
{								\
	[0 ... BITS_TO_LONGS(NR_CPUS)-2] = ~0UL,		\
	[BITS_TO_LONGS(NR_CPUS)-1] = BITMAP_LAST_WORD_MASK(NR_CPUS)	\
}
#endif /* NR_CPUS > BITS_PER_LONG */

/**
 * cpumap_print_to_pagebuf  - copies the cpumask into the buffer either
 *	as comma-separated list of cpus or hex values of cpumask
 * @list: indicates whether the cpumap must be list
 * @mask: the cpumask to copy
 * @buf: the buffer to copy into
 *
 * Returns the length of the (null-terminated) @buf string, zero if
 * nothing is copied.
 */
static inline ssize_t
cpumap_print_to_pagebuf(bool list, char *buf, const struct cpumask *mask)
{
	return bitmap_print_to_pagebuf(list, buf, cpumask_bits(mask),
				      nr_cpu_ids);
}

/*
 * IAMROOT, 2021.11.13:
 * CPU_BITS_ALL과 비슷하다.
 * 단, bitmap을 cpumask_t안에 감쌌다.
 */
#if NR_CPUS <= BITS_PER_LONG
#define CPU_MASK_ALL							\
(cpumask_t) { {								\
	[BITS_TO_LONGS(NR_CPUS)-1] = BITMAP_LAST_WORD_MASK(NR_CPUS)	\
} }
#else
#define CPU_MASK_ALL							\
(cpumask_t) { {								\
	[0 ... BITS_TO_LONGS(NR_CPUS)-2] = ~0UL,			\
	[BITS_TO_LONGS(NR_CPUS)-1] = BITMAP_LAST_WORD_MASK(NR_CPUS)	\
} }
#endif /* NR_CPUS > BITS_PER_LONG */

#define CPU_MASK_NONE							\
(cpumask_t) { {								\
	[0 ... BITS_TO_LONGS(NR_CPUS)-1] =  0UL				\
} }

#define CPU_MASK_CPU0							\
(cpumask_t) { {								\
	[0] =  1UL							\
} }

#endif /* __LINUX_CPUMASK_H */
