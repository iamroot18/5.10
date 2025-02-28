/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * ARM Power State and Coordination Interface (PSCI) header
 *
 * This header holds common PSCI defines and macros shared
 * by: ARM kernel, ARM64 kernel, KVM ARM/ARM64 and user space.
 *
 * Copyright (C) 2014 Linaro Ltd.
 * Author: Anup Patel <anup.patel@linaro.org>
 */

#ifndef _UAPI_LINUX_PSCI_H
#define _UAPI_LINUX_PSCI_H

/*
 * PSCI v0.1 interface
 *
 * The PSCI v0.1 function numbers are implementation defined.
 *
 * Only PSCI return values such as: SUCCESS, NOT_SUPPORTED,
 * INVALID_PARAMS, and DENIED defined below are applicable
 * to PSCI v0.1.
 */

/* PSCI v0.2 interface */
#define PSCI_0_2_FN_BASE			0x84000000
#define PSCI_0_2_FN(n)				(PSCI_0_2_FN_BASE + (n))
#define PSCI_0_2_64BIT				0x40000000
#define PSCI_0_2_FN64_BASE			\
					(PSCI_0_2_FN_BASE + PSCI_0_2_64BIT)
#define PSCI_0_2_FN64(n)			(PSCI_0_2_FN64_BASE + (n))

#define PSCI_0_2_FN_PSCI_VERSION		PSCI_0_2_FN(0)
#define PSCI_0_2_FN_CPU_SUSPEND			PSCI_0_2_FN(1)
#define PSCI_0_2_FN_CPU_OFF			PSCI_0_2_FN(2)
#define PSCI_0_2_FN_CPU_ON			PSCI_0_2_FN(3)
#define PSCI_0_2_FN_AFFINITY_INFO		PSCI_0_2_FN(4)
#define PSCI_0_2_FN_MIGRATE			PSCI_0_2_FN(5)
#define PSCI_0_2_FN_MIGRATE_INFO_TYPE		PSCI_0_2_FN(6)
#define PSCI_0_2_FN_MIGRATE_INFO_UP_CPU		PSCI_0_2_FN(7)
#define PSCI_0_2_FN_SYSTEM_OFF			PSCI_0_2_FN(8)
#define PSCI_0_2_FN_SYSTEM_RESET		PSCI_0_2_FN(9)

#define PSCI_0_2_FN64_CPU_SUSPEND		PSCI_0_2_FN64(1)
#define PSCI_0_2_FN64_CPU_ON			PSCI_0_2_FN64(3)
#define PSCI_0_2_FN64_AFFINITY_INFO		PSCI_0_2_FN64(4)
#define PSCI_0_2_FN64_MIGRATE			PSCI_0_2_FN64(5)
#define PSCI_0_2_FN64_MIGRATE_INFO_UP_CPU	PSCI_0_2_FN64(7)

#define PSCI_1_0_FN_PSCI_FEATURES		PSCI_0_2_FN(10)
#define PSCI_1_0_FN_SYSTEM_SUSPEND		PSCI_0_2_FN(14)
#define PSCI_1_0_FN_SET_SUSPEND_MODE		PSCI_0_2_FN(15)
#define PSCI_1_1_FN_SYSTEM_RESET2		PSCI_0_2_FN(18)

#define PSCI_1_0_FN64_SYSTEM_SUSPEND		PSCI_0_2_FN64(14)
#define PSCI_1_1_FN64_SYSTEM_RESET2		PSCI_0_2_FN64(18)

/* PSCI v0.2 power state encoding for CPU_SUSPEND function */
#define PSCI_0_2_POWER_STATE_ID_MASK		0xffff
#define PSCI_0_2_POWER_STATE_ID_SHIFT		0
#define PSCI_0_2_POWER_STATE_TYPE_SHIFT		16
#define PSCI_0_2_POWER_STATE_TYPE_MASK		\
				(0x1 << PSCI_0_2_POWER_STATE_TYPE_SHIFT)
#define PSCI_0_2_POWER_STATE_AFFL_SHIFT		24
#define PSCI_0_2_POWER_STATE_AFFL_MASK		\
				(0x3 << PSCI_0_2_POWER_STATE_AFFL_SHIFT)

/* PSCI extended power state encoding for CPU_SUSPEND function */
#define PSCI_1_0_EXT_POWER_STATE_ID_MASK	0xfffffff
#define PSCI_1_0_EXT_POWER_STATE_ID_SHIFT	0
#define PSCI_1_0_EXT_POWER_STATE_TYPE_SHIFT	30
#define PSCI_1_0_EXT_POWER_STATE_TYPE_MASK	\
				(0x1 << PSCI_1_0_EXT_POWER_STATE_TYPE_SHIFT)

/* PSCI v0.2 affinity level state returned by AFFINITY_INFO */
#define PSCI_0_2_AFFINITY_LEVEL_ON		0
#define PSCI_0_2_AFFINITY_LEVEL_OFF		1
#define PSCI_0_2_AFFINITY_LEVEL_ON_PENDING	2

/* PSCI v0.2 multicore support in Trusted OS returned by MIGRATE_INFO_TYPE */
/*
 * IAMROOT, 2021.12.18:
 * - PSCI_0_2_TOS_UP_MIGRATE
 *   해당 cpu하나에서만 동작을 하고 있고 다른 cpu로 이동이 가능한경우
 * - PSCI_0_2_TOS_UP_NO_MIGRATE
 *   해당 cpu말고 다른 cpu로 이동이 불가능한경우
 * - PSCI_0_2_TOS_MP
 *   multi core로 동작하고 있는 경우
 *
 * - ex) cpu 0, 1, 2가 있는 상황에서 secure firmware가 0번 cpu에
 *   동작을 하고 있다고 가정을 했을때.
 *   PSCI_0_2_TOS_UP_MIGRATE 이면 1, 2번 cpu로 이동 가능
 *   PSCI_0_2_TOS_UP_NO_MIGRATE 이면 0번 cpu에서만 동작이 가능한 상태.
 *   PSCI_0_2_TOS_MP 이 경우엔 multi core로 동작이 가능하므로 migrate를
 *   할 필요가 없는 상태.
 */
#define PSCI_0_2_TOS_UP_MIGRATE			0
#define PSCI_0_2_TOS_UP_NO_MIGRATE		1
#define PSCI_0_2_TOS_MP				2

/* PSCI version decoding (independent of PSCI version) */
#define PSCI_VERSION_MAJOR_SHIFT		16
#define PSCI_VERSION_MINOR_MASK			\
		((1U << PSCI_VERSION_MAJOR_SHIFT) - 1)
#define PSCI_VERSION_MAJOR_MASK			~PSCI_VERSION_MINOR_MASK
#define PSCI_VERSION_MAJOR(ver)			\
		(((ver) & PSCI_VERSION_MAJOR_MASK) >> PSCI_VERSION_MAJOR_SHIFT)
#define PSCI_VERSION_MINOR(ver)			\
		((ver) & PSCI_VERSION_MINOR_MASK)
#define PSCI_VERSION(maj, min)						\
	((((maj) << PSCI_VERSION_MAJOR_SHIFT) & PSCI_VERSION_MAJOR_MASK) | \
	 ((min) & PSCI_VERSION_MINOR_MASK))

/* PSCI features decoding (>=1.0) */
#define PSCI_1_0_FEATURES_CPU_SUSPEND_PF_SHIFT	1
#define PSCI_1_0_FEATURES_CPU_SUSPEND_PF_MASK	\
			(0x1 << PSCI_1_0_FEATURES_CPU_SUSPEND_PF_SHIFT)

#define PSCI_1_0_OS_INITIATED			BIT(0)
#define PSCI_1_0_SUSPEND_MODE_PC		0
#define PSCI_1_0_SUSPEND_MODE_OSI		1

/* PSCI return values (inclusive of all PSCI versions) */
#define PSCI_RET_SUCCESS			0
#define PSCI_RET_NOT_SUPPORTED			-1
#define PSCI_RET_INVALID_PARAMS			-2
#define PSCI_RET_DENIED				-3
#define PSCI_RET_ALREADY_ON			-4
#define PSCI_RET_ON_PENDING			-5
#define PSCI_RET_INTERNAL_FAILURE		-6
#define PSCI_RET_NOT_PRESENT			-7
#define PSCI_RET_DISABLED			-8
#define PSCI_RET_INVALID_ADDRESS		-9

#endif /* _UAPI_LINUX_PSCI_H */
