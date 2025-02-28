/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_VMACACHE_H
#define __LINUX_VMACACHE_H

#include <linux/sched.h>
#include <linux/mm.h>

static inline void vmacache_flush(struct task_struct *tsk)
{
	memset(tsk->vmacache.vmas, 0, sizeof(tsk->vmacache.vmas));
}

extern void vmacache_update(unsigned long addr, struct vm_area_struct *newvma);
extern struct vm_area_struct *vmacache_find(struct mm_struct *mm,
						    unsigned long addr);

#ifndef CONFIG_MMU
extern struct vm_area_struct *vmacache_find_exact(struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end);
#endif

/*
 * IAMROOT, 2022.05.28:
 * - vma가 변경됬을때 ++함으로써 변경됬음을 표시한다.
 *   후에 무효화시킬것.
 */
static inline void vmacache_invalidate(struct mm_struct *mm)
{
	mm->vmacache_seqnum++;
}

#endif /* __LINUX_VMACACHE_H */
