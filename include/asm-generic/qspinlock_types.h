/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Queued spinlock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 *
 * Authors: Waiman Long <waiman.long@hp.com>
 */
#ifndef __ASM_GENERIC_QSPINLOCK_TYPES_H
#define __ASM_GENERIC_QSPINLOCK_TYPES_H

#include <linux/types.h>

/*
 * IAMROOT, 2021.09.25: 
 * arch_spinlock_t: qspinlock 구조체를 타입 정의하여 사용한다.
 * u32 val - u16 locked_pending - u8 locked
 *                                u8 pending
 *           u16 tail
 */
typedef struct qspinlock {
	union {
		atomic_t val;

		/*
		 * By using the whole 2nd least significant byte for the
		 * pending bit, we can allow better optimization of the lock
		 * acquisition for the pending bit holder.
		 */
#ifdef __LITTLE_ENDIAN
		struct {
			u8	locked;
			u8	pending;
		};
		struct {
			u16	locked_pending;
			u16	tail;
		};
#else
		struct {
			u16	tail;
			u16	locked_pending;
		};
		struct {
			u8	reserved[2];
			u8	pending;
			u8	locked;
		};
#endif
	};
} arch_spinlock_t;

/*
 * Initializier
 */
#define	__ARCH_SPIN_LOCK_UNLOCKED	{ { .val = ATOMIC_INIT(0) } }
/*
 * Bitfields in the atomic value:
 *
 * When NR_CPUS < 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-15: not used
 * 16-17: tail index
 * 18-31: tail cpu (+1)
 *
 * When NR_CPUS >= 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-10: tail index
 * 11-31: tail cpu (+1)
 */
/*
 * IAMROOT, 2021.10.02:
 * - _Q_LOCKED_MASK : 0xff
 *   arch_spinlock_t 에서 locked 값을 masking하기 위한것.
 * - _Q_PENDING_MASK : 0xff00
 *   arch_spinlock_t 에서 pending 값을 masking하기 위한것.
 * - _Q_TAIL_IDX_MASK : 0x3_0000
 * - _Q_TAIL_CPU_MASK : 0xfffc_0000
 * - _Q_TAIL_MASK : 0xffff_0000
 *
 * - _Q_PENDING_OFFSET : 8 
 * - _Q_TAIL_IDX_OFFSET : 16
 * - _Q_TAIL_CPU_OFFSET : 18
 *
 * - _Q_LOCKED_VAL = 1
 * - _Q_PENDING_VAL = 0x100
 */
#define	_Q_SET_MASK(type)	(((1U << _Q_ ## type ## _BITS) - 1)\
				      << _Q_ ## type ## _OFFSET)
#define _Q_LOCKED_OFFSET	0
#define _Q_LOCKED_BITS		8
#define _Q_LOCKED_MASK		_Q_SET_MASK(LOCKED)

#define _Q_PENDING_OFFSET	(_Q_LOCKED_OFFSET + _Q_LOCKED_BITS)
#if CONFIG_NR_CPUS < (1U << 14)
#define _Q_PENDING_BITS		8
#else
#define _Q_PENDING_BITS		1
#endif
#define _Q_PENDING_MASK		_Q_SET_MASK(PENDING)

#define _Q_TAIL_IDX_OFFSET	(_Q_PENDING_OFFSET + _Q_PENDING_BITS)
#define _Q_TAIL_IDX_BITS	2
#define _Q_TAIL_IDX_MASK	_Q_SET_MASK(TAIL_IDX)

#define _Q_TAIL_CPU_OFFSET	(_Q_TAIL_IDX_OFFSET + _Q_TAIL_IDX_BITS)
#define _Q_TAIL_CPU_BITS	(32 - _Q_TAIL_CPU_OFFSET)
#define _Q_TAIL_CPU_MASK	_Q_SET_MASK(TAIL_CPU)

#define _Q_TAIL_OFFSET		_Q_TAIL_IDX_OFFSET
#define _Q_TAIL_MASK		(_Q_TAIL_IDX_MASK | _Q_TAIL_CPU_MASK)

#define _Q_LOCKED_VAL		(1U << _Q_LOCKED_OFFSET)
#define _Q_PENDING_VAL		(1U << _Q_PENDING_OFFSET)

#endif /* __ASM_GENERIC_QSPINLOCK_TYPES_H */
