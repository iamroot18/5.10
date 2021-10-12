/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#error "Please don't include <linux/compiler-gcc.h> directly, include <linux/compiler.h> instead."
#endif

/*
 * Common definitions for all gcc versions go here.
 */
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)

/* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=58145 */
#if GCC_VERSION < 40900
# error Sorry, your version of GCC is too old - please use 4.9 or newer.
#endif

/*
 * IAMROOT, 2021.10.12:
 * - 참고 : http://egloos.zum.com/studyfoss/v/5374731
 *
 *   RELOC_HIDE(p, offset) = (unsigned long)p + offset
 *   
 *   이렇게 type변환후 offset을 더한 의미밖에없다.
 *
 *   그럼에도 이걸 쓰는 이유는 만약 p가 Type *p라는 정의고 offset이 Type을
 *   넘는 범위라고 할때 compiler가 잘못된 접근인줄 알고 의도치 않는 코드를
 *   생성할수 있다고 한다.
 *
 *   그래도 일반적인 경우엔 사용할 일이 없으며 굳이 쓴다면 per cpu관련 메모리를
 *   사용할때 사용한다고 한다. per cpu관련 메모리는 compile 시점에서는
 *   1개만 존재하지만 runtime때 cpu만큼늘어나고, 이걸 고려해서 작성되어 있는데
 *   compiler는 이를 고려하지 않아 잘못된 code를 생성할수 있다는것이다.
 *
 *   그래서 compiler에 아에 이런 주소관련 정보를 감추기 위해 inline asm으로
 *   작성되었다는 것이다.
 */
/*
 * This macro obfuscates arithmetic on a variable address so that gcc
 * shouldn't recognize the original var, and make assumptions about it.
 *
 * This is needed because the C standard makes it undefined to do
 * pointer arithmetic on "objects" outside their boundaries and the
 * gcc optimizers assume this is the case. In particular they
 * assume such arithmetic does not wrap.
 *
 * A miscompilation has been observed because of this on PPC.
 * To work around it we hide the relationship of the pointer and the object
 * using this macro.
 *
 * Versions of the ppc64 compiler before 4.1 had a bug where use of
 * RELOC_HIDE could trash r30. The bug can be worked around by changing
 * the inline assembly constraint from =g to =r, in this particular
 * case either is valid.
 */
#define RELOC_HIDE(ptr, off)						\
({									\
	unsigned long __ptr;						\
	__asm__ ("" : "=r"(__ptr) : "0"(ptr));				\
	(typeof(ptr)) (__ptr + (off));					\
})
/*
 * IAMROOT, 2021.09.11:
 * - retpoline 참고 :https://blog.alyac.co.kr/1479
 * - __indirect_branch__('choice')
 * On x86 targets, the indirect_branch attribute causes the compiler
 * to convert indirect call and jump with choice. ‘keep’ keeps indirect call
 * and jump unmodified. ‘thunk’ converts indirect call and jump to call and
 * return thunk. ‘thunk-inline’ converts indirect call and jump to inlined call
 * and return thunk. ‘thunk-extern’ converts indirect call and jump to
 * external call and return thunk provided in a separate object file.
 */
#ifdef CONFIG_RETPOLINE
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#endif

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#define __compiletime_object_size(obj) __builtin_object_size(obj, 0)

#define __compiletime_warning(message) __attribute__((__warning__(message)))
#define __compiletime_error(message) __attribute__((__error__(message)))
/*
 * IAMROOT, 2021.09.11:
 * 참고 : https://pincette.tistory.com/12
 * This gcc plugin generates some entropy from program state throughout
 * the uptime of the kernel. It has small performance loss.
 * The plugin uses an attribute which can be on a function
 * (to extract entropy beyond init functions) or on a variable
 * (to initialize it with a random number generated at compile time) 
 */
#if defined(LATENT_ENTROPY_PLUGIN) && !defined(__CHECKER__)
#define __latent_entropy __attribute__((latent_entropy))
#endif

/*
 * calling noreturn functions, __builtin_unreachable() and __builtin_trap()
 * confuse the stack allocation in gcc, leading to overly large stack
 * frames, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82365
 *
 * Adding an empty inline assembly before it works around the problem
 */
#define barrier_before_unreachable() asm volatile("")

/*
 * Mark a position in code as unreachable.  This can be used to
 * suppress control flow warnings after asm blocks that transfer
 * control elsewhere.
 */
#define unreachable() \
	do {					\
		annotate_unreachable();		\
		barrier_before_unreachable();	\
		__builtin_unreachable();	\
	} while (0)

#if defined(RANDSTRUCT_PLUGIN) && !defined(__CHECKER__)
#define __randomize_layout __attribute__((randomize_layout))
#define __no_randomize_layout __attribute__((no_randomize_layout))
/* This anon struct can add padding, so only enable it under randstruct. */
#define randomized_struct_fields_start	struct {
#define randomized_struct_fields_end	} __randomize_layout;
#endif

/*
 * GCC 'asm goto' miscompiles certain code sequences:
 *
 *   http://gcc.gnu.org/bugzilla/show_bug.cgi?id=58670
 *
 * Work it around via a compiler barrier quirk suggested by Jakub Jelinek.
 *
 * (asm goto is automatically volatile - the naming reflects this.)
 */
#define asm_volatile_goto(x...)	do { asm goto(x); asm (""); } while (0)

/*
 * sparse (__CHECKER__) pretends to be gcc, but can't do constant
 * folding in __builtin_bswap*() (yet), so don't set these for it.
 */
#if defined(CONFIG_ARCH_USE_BUILTIN_BSWAP) && !defined(__CHECKER__)
#define __HAVE_BUILTIN_BSWAP32__
#define __HAVE_BUILTIN_BSWAP64__
#define __HAVE_BUILTIN_BSWAP16__
#endif /* CONFIG_ARCH_USE_BUILTIN_BSWAP && !__CHECKER__ */

#if GCC_VERSION >= 70000
#define KASAN_ABI_VERSION 5
#elif GCC_VERSION >= 50000
#define KASAN_ABI_VERSION 4
#elif GCC_VERSION >= 40902
#define KASAN_ABI_VERSION 3
#endif
/*
 * IAMROOT, 2021.09.11:
 * - sanitize address option이 켜졋을시 사용안하게 하는것.
 */
#if __has_attribute(__no_sanitize_address__)
#define __no_sanitize_address __attribute__((no_sanitize_address))
#else
#define __no_sanitize_address
#endif

#if defined(__SANITIZE_THREAD__) && __has_attribute(__no_sanitize_thread__)
#define __no_sanitize_thread __attribute__((no_sanitize_thread))
#else
#define __no_sanitize_thread
#endif

#if __has_attribute(__no_sanitize_undefined__)
#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
#else
#define __no_sanitize_undefined
#endif

#if GCC_VERSION >= 50100
#define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
#endif

/*
 * Turn individual warnings and errors on and off locally, depending
 * on version.
 */
#define __diag_GCC(version, severity, s) \
	__diag_GCC_ ## version(__diag_GCC_ ## severity s)

/* Severity used in pragma directives */
#define __diag_GCC_ignore	ignored
#define __diag_GCC_warn		warning
#define __diag_GCC_error	error

#define __diag_str1(s)		#s
#define __diag_str(s)		__diag_str1(s)
#define __diag(s)		_Pragma(__diag_str(GCC diagnostic s))

#if GCC_VERSION >= 80000
#define __diag_GCC_8(s)		__diag(s)
#else
#define __diag_GCC_8(s)
#endif
