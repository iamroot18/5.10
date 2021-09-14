/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TASK_STACK_H
#define _LINUX_SCHED_TASK_STACK_H

/*
 * task->stack (kernel stack) handling interfaces:
 */

#include <linux/sched.h>
#include <linux/magic.h>
/*
 * IAMROOT, 2021.09.11:
 * - thread_info가 task 안에 있는 경우 stack을 그대로 사용한다.
 *   그렇지 않은 경우엔 thread_info가 stack에 존재하기 때문에 그거를 고려한다.
 *   (include/linux/sched.h thread_union 주석 참고)
 */
#ifdef CONFIG_THREAD_INFO_IN_TASK

/*
 * When accessing the stack of a non-current task that might exit, use
 * try_get_task_stack() instead.  task_stack_page will return a pointer
 * that could get freed out from under you.
 */
static inline void *task_stack_page(const struct task_struct *task)
{
	return task->stack;
}

#define setup_thread_stack(new,old)	do { } while(0)

/*
 * IAMROOT, 2021.09.14:
 * CONFIG_THREAD_INFO_IN_TASK on. task_info는 struct task안에 존재 하므로
 * thread_stack엔 아무것도 없다. 첫주소가 stack의 끝이다.
 */
static inline unsigned long *end_of_stack(const struct task_struct *task)
{
	return task->stack;
}

#elif !defined(__HAVE_THREAD_FUNCTIONS)

#define task_stack_page(task)	((void *)(task)->stack)

static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);
	task_thread_info(p)->task = p;
}

/*
 * IAMROOT, 2021.09.14:
 * CONFIG_THREAD_INFO_IN_TASK off. task_info는 stack의 시작지부터 존재한다.
 * 
 * -GROW UP
 *  task_thread_info(p)를 통해서 task_info의 시작번지를 구해오는데, 이 시작
 *  번지 자체가 stack의 시작번지이므로, stack의 end는 자연스럽게
 *  THREAD_SIZE -1로 하면 나온다.
 *
 * +--------- stack ---------------------------------------> TASK_SIZE
 * +--task_info ->|stack start                             | stack end
 *
 * -GROW DOWN
 *  task_thread_info(p)를 통해서 task_info의 시작번지를 구해오는데, 여기에 +1
 *  을하여 thread_info의 끝주소를 구해오며, 이 끝주소가 stack의 end 주소가된다.
 *
 * +--------- stack ---------------------------------------> TASK_SIZE
 * +--task_info ->|stack end                               | stack start
 */
/*
 * Return the address of the last usable long on the stack.
 *
 * When the stack grows down, this is just above the thread
 * info struct. Going any lower will corrupt the threadinfo.
 *
 * When the stack grows up, this is the highest address.
 * Beyond that position, we corrupt data on the next page.
 */
static inline unsigned long *end_of_stack(struct task_struct *p)
{
/*
 * IAMROOT, 2021.09.11:
 * - arm, arm64는 보통 GROW DOWN이다
 */
#ifdef CONFIG_STACK_GROWSUP
	return (unsigned long *)((unsigned long)task_thread_info(p) + THREAD_SIZE) - 1;
#else
	return (unsigned long *)(task_thread_info(p) + 1);
#endif
}

#endif

#ifdef CONFIG_THREAD_INFO_IN_TASK
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return refcount_inc_not_zero(&tsk->stack_refcount) ?
		task_stack_page(tsk) : NULL;
}

extern void put_task_stack(struct task_struct *tsk);
#else
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return task_stack_page(tsk);
}

static inline void put_task_stack(struct task_struct *tsk) {}
#endif

#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)

static inline int object_is_on_stack(const void *obj)
{
	void *stack = task_stack_page(current);

	return (obj >= stack) && (obj < (stack + THREAD_SIZE));
}

extern void thread_stack_cache_init(void);

#ifdef CONFIG_DEBUG_STACK_USAGE
static inline unsigned long stack_not_used(struct task_struct *p)
{
	unsigned long *n = end_of_stack(p);

	do { 	/* Skip over canary */
# ifdef CONFIG_STACK_GROWSUP
		n--;
# else
		n++;
# endif
	} while (!*n);

# ifdef CONFIG_STACK_GROWSUP
	return (unsigned long)end_of_stack(p) - (unsigned long)n;
# else
	return (unsigned long)n - (unsigned long)end_of_stack(p);
# endif
}
#endif
extern void set_task_stack_end_magic(struct task_struct *tsk);

#ifndef __HAVE_ARCH_KSTACK_END
static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection:
	 * Some APM bios versions misalign the stack
	 */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}
#endif

#endif /* _LINUX_SCHED_TASK_STACK_H */
