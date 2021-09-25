/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 ARM Ltd.
 */
#ifndef __ASM_VDSO_PROCESSOR_H
#define __ASM_VDSO_PROCESSOR_H

#ifndef __ASSEMBLY__

/*
 * IAMROOT, 2021.09.25: 
 * - yield 어셈블리 명령은 아키텍처에게 hint를 주는데,
 *   다른 스레드(미래의 dual hw thread)에게 파이프라인의 실행 유닛등을 양보할
 *   수 있다. 
 *
 * - 현재까지 출시된 ARM64 core들은 single hw thread per core 이므로 
 *   nop와 거의 유사할 것이라 추측함.
 */
static inline void cpu_relax(void)
{
	asm volatile("yield" ::: "memory");
}

#endif /* __ASSEMBLY__ */

#endif /* __ASM_VDSO_PROCESSOR_H */
