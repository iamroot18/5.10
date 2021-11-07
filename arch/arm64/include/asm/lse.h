/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_LSE_H
#define __ASM_LSE_H

#include <asm/atomic_ll_sc.h>

#ifdef CONFIG_ARM64_LSE_ATOMICS

#define __LSE_PREAMBLE	".arch_extension lse\n"

#include <linux/compiler_types.h>
#include <linux/export.h>
#include <linux/jump_label.h>
#include <linux/stringify.h>
#include <asm/alternative.h>
#include <asm/atomic_lse.h>
#include <asm/cpucaps.h>

extern struct static_key_false cpu_hwcap_keys[ARM64_NCAPS];
extern struct static_key_false arm64_const_caps_ready;

/*
 * IAMROOT, 2021.11.05:
 * arch/arm64/kernel/cpufeature.c
 * - arm64_features
 * - init_cpu_hwcaps_indirect_list
 * - init_cpu_hwcaps_indirect_list_from_array
 * - enable_cpu_capabilities
 * 참조.
 *
 * LSE config가 true이고 Hardware가 LSE를 지원하면
 * LSE를 사용하고, 그렇지 않으면 LL/SC를 사용한다.
 */
static inline bool system_uses_lse_atomics(void)
{
	return (static_branch_likely(&arm64_const_caps_ready)) &&
		static_branch_likely(&cpu_hwcap_keys[ARM64_HAS_LSE_ATOMICS]);
}

/*
 * IAMROOT, 2021.11.05:
 * LSE config가 true인 경우에는
 * Hardware지원 여부에 따라 LSE 혹은 LL/SC를 사용한다.
 */
#define __lse_ll_sc_body(op, ...)					\
({									\
	system_uses_lse_atomics() ?					\
		__lse_##op(__VA_ARGS__) :				\
		__ll_sc_##op(__VA_ARGS__);				\
})

/* In-line patching at runtime */
#define ARM64_LSE_ATOMIC_INSN(llsc, lse)				\
	ALTERNATIVE(llsc, __LSE_PREAMBLE lse, ARM64_HAS_LSE_ATOMICS)

#else	/* CONFIG_ARM64_LSE_ATOMICS */

/*
 * IAMROOT, 2021.11.05:
 * LSE config가 false인 경우에는 LL/SC를 쓴다.
 */
static inline bool system_uses_lse_atomics(void) { return false; }

#define __lse_ll_sc_body(op, ...)		__ll_sc_##op(__VA_ARGS__)

#define ARM64_LSE_ATOMIC_INSN(llsc, lse)	llsc

#endif	/* CONFIG_ARM64_LSE_ATOMICS */
#endif	/* __ASM_LSE_H */
