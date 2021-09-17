/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <linux/compiler.h>
#include <linux/types.h>

/* Built-in __init functions needn't be compiled with retpoline */
#if defined(__noretpoline) && !defined(MODULE)
#define __noinitretpoline __noretpoline
#else
#define __noinitretpoline
#endif

/* These macros are used to mark some functions or 
 * initialized data (doesn't apply to uninitialized data)
 * as `initialization' functions. The kernel can take this
 * as hint that the function is used only during the initialization
 * phase and free up used memory resources after
 *
 * Usage:
 * For functions:
 * 
 * You should add __init immediately before the function name, like:
 *
 * static void __init initme(int x, int y)
 * {
 *    extern int z; z = x * y;
 * }
 *
 * If the function has a prototype somewhere, you can also add
 * __init between closing brace of the prototype and semicolon:
 *
 * extern int initialize_foobar_device(int, int, int) __init;
 *
 * For initialized data:
 * You should insert __initdata or __initconst between the variable name
 * and equal sign followed by value, e.g.:
 *
 * static int init_variable __initdata = 0;
 * static const char linux_logo[] __initconst = { 0x32, 0x36, ... };
 *
 * Don't forget to initialize data not at file scope, i.e. within a function,
 * as gcc otherwise puts the data into the bss section and not into the init
 * section.
 */

/*
 * IAMROOT, 2021.09.18:
 *
 * __section(.init.text): .init.text(초기화 함수용 영역)영역에 해당 함수를 배치.
 *
 * __cold: 이 함수는 실행될 가능성이 작다는 것을 커널에 알림. (속도보다는 메모리 최적화에 이용)
 *
 * __latent_entropy:
 *   커널에서 모든 randomness의 근원은 entropy pool이다. 대략 4,096 bits의 아주 큰 숫자가
 *   커널 메모리에 private하게 보존되어 있다. 다시 말하면 2^4096 개의 숫자를 표현할 수 있으며
 *   4,096 bits의 엔트로피까지 포함할 수 있다고 표현한다. entropy pool은 두가지 용도로 사용된다.
 *   1. Random number가 entropy pool을 기반으로 생성된다.
 *   2. entropy를 entropy pool에 주입한다.
 *   Random number가 생성될 때 마다 entropy pool의 entropy는 감소한다. 왜냐하면 Random number를
 *   받는 쪽에서 pool자체에 대한 일부 정보를 갖게 되기 때문이다. 따라서 충분한 randomness를 보장
 *   하기 위해서는 entropy를 보충하는 일이 매우 중요하다.
 *   entropy를 보충하기 위한 하나의 방법으로서 __latent_entropy라는 플래그가 사용된다.
 *   이런 초기화 함수 외에도 HW 인터럽트 시에도 entropy를 보충하는 방법들을 사용한다고 한다.
 *
 * __noinitretpoline:
 *   CPU의 보안 취약점인 Spectre의 대책으로서 Retpoline을 사용하지 않겠다는 의미이다.
 *   초기화 코드에서는 Spectre의 영향을 받지 않기 때문에, performance가 저하되는
 *   Retpoline을 회피하기 위한 것이다.
 *
 * Retpoline은 무엇인가?
 *   우선 indirect branch의 최적화와 그에 따른 부작용에 대해서 알아야한다.
 *
 *   mov ebx, dest_address
 *   jmp ebx
 *
 *   예를 들어서 위와 같은 것이 하나의 indirect branch의 예가 될 것이다.
 *   위의 jmp명령이 loop안에서 반복해서 실행된다고 생각해 보자. 이 경우에
 *   jmp의 target address를 예측하는 것은 pipeline 성능에 있어서 굉장히 중요하다.
 *   따라서 BTB (Branch Target Buffer)라는 것에다가 jmp ebx 명령의 instruction 주소와
 *   이전 target address를 매핑시켜 놓는다. 만약에 다시 한 번 jmp ebx 명령이 실행 되면
 *   target address를 BTB에서 predict해서 바로 fetch시키게 되는 것이다.
 *
 *   여기서 BHB(Branch History Buffer) 라는 개념도 등장하게 되는데, 이거는
 *   이전의 예측이 맞았는지 틀렸는지를 기록하는 buffer라고 생각할 수 있다.
 *
 *   이제 이 BTB와 BHB가 attacker에 의해서 어떻게 이용될 수 있는지를 알아보자.
 *   BTB와 BHB는 CPU의 내부에 한개씩 밖에 존재하지 않는다고 한다. 이를 다시 말하면
 *   커널모드와 유저모드를 구별하지 않는 다는 말이다. 만약에, attacker가 유저모드에서
 *   BTB와 BHB를 자기가 원하는 방향으로 학습시킨다면 어떻게 될까? 여기에 그 취약점이
 *   있는 것이다.
 *
 *   이를 해결하기 위해 나온 것이 Retpoline이다.
 *   이를 이해하기 위해서는 ROP (Return Oriented Programming)의 개념을 이해할 필요가 있다.
 *
 *   push addr_1	// ①
 *   call addr_2	// ②
 *   addr_1:	xxxxx...	// ③
 *   :
 *   :
 *   addr_2:	yyyyy.....	// ④
 *   :
 *   ret		// ⑤
 *
 *   위의 프로그램의 실행순서는 1->2->4->5->3이다. 2에서 addr_2를 call하기 전에
 *   1에서 addr_1의 주소를 스택에 push해 두었다. 따라서 5에서 addr_2이 ret하게 되면
 *   call하기 직전에 스택에 쌓여있는 주소 addr_1으로 jump하게 되는 것이다.
 *
 *   push addr_1	// ①
 *   push addr_2	// ②
 *   push addr_3	// ③
 *   :
 *   ret		// ④
 *   addr_1:	xxxxx...	// ⑤
 *   :
 *   ret		// ⑥
 *   addr_2:	yyyyy.....	// ⑦
 *   :
 *   ret		// ⑧
 *   addr_2:	zzzzz.....	// ⑨
 *   :
 *   ret		// ⑩
 *
 *   위의 프로그램의 실행순서는 1->2->3-> ... ->10이다.
 *   이렇게 Stack에 들어있는 return address를 이용하게 되면 BTB, BTH를 사용하지 않고
 *   RSB(Return Stack Buffer)라 불리는 다른 종류의 buffer를 사용하기 때문에 위의
 *   취약점을 해결할 수 있다고 한다.
 *
 *   __attribute__((__indirect_branch__("keep"))) -> Retpoline을 사용하지 않음.
 *   __attribute__((__indirect_branch__("thunk"))) -> Retpoiine을 사용함.
 *
 *   keep은 위의 jmp명령을 사용하는 것이고
 *   thunk는 위의 ret명령을 사용하는 것이라고 생각하면 될 것 같다.
 *
 *   GCC 컴파일러가 위의 attribute에 따라 의도에 맞는 코드를 생성해 줄 것이다.
 *
 *   https://debimate.jp/2019/04/29/
 *   https://blog.cloudflare.com/ensuring-randomness-with-linuxs-random-number-generator/
 *   https://pc.watch.impress.co.jp/docs/topic/feature/1176718.html
 */
/* These are for everybody (although not all archs will actually
   discard it in modules) */
#define __init		__section(".init.text") __cold  __latent_entropy __noinitretpoline

/*
 * IAMROOT, 2021.09.04:
 * - kernel 초기화가 끝나면 free 할 section
 */
#define __initdata	__section(".init.data")
#define __initconst	__section(".init.rodata")
#define __exitdata	__section(".exit.data")
#define __exit_call	__used __section(".exitcall.exit")

/*
 * modpost check for section mismatches during the kernel build.
 * A section mismatch happens when there are references from a
 * code or data section to an init section (both code or data).
 * The init sections are (for most archs) discarded by the kernel
 * when early init has completed so all such references are potential bugs.
 * For exit sections the same issue exists.
 *
 * The following markers are used for the cases where the reference to
 * the *init / *exit section (code or data) is valid and will teach
 * modpost not to issue a warning.  Intended semantics is that a code or
 * data tagged __ref* can reference code or data from init section without
 * producing a warning (of course, no warning does not mean code is
 * correct, so optimally document why the __ref is needed and why it's OK).
 *
 * The markers follow same syntax rules as __init / __initdata.
 */
#define __ref            __section(".ref.text") noinline
#define __refdata        __section(".ref.data")
#define __refconst       __section(".ref.rodata")

#ifdef MODULE
#define __exitused
#else
#define __exitused  __used
#endif

#define __exit          __section(".exit.text") __exitused __cold notrace

/* Used for MEMORY_HOTPLUG */
#define __meminit        __section(".meminit.text") __cold notrace \
						  __latent_entropy
#define __meminitdata    __section(".meminit.data")
#define __meminitconst   __section(".meminit.rodata")
#define __memexit        __section(".memexit.text") __exitused __cold notrace
#define __memexitdata    __section(".memexit.data")
#define __memexitconst   __section(".memexit.rodata")

/* For assembly routines */

/*
 * IAMROOT, 2021.07.10: 
 * - .setion의 의미 : 컴파일시 코드가 특정섹션에 들어갈 수 있게 하는  지시어. 
 * - .head.text 영역
 * - ax 의미
 *   -> allocatable(runtime시에 메모리에 로드된다) & excutable(실행 할 수있다),
 * - ax가 꼭필요한가?
 *   -> 각자 숙제로 확인.
 * - etc:
 *   merges the two sections named sectionX into one section with the flags "ax".
 *   https://developer.arm.com/documentation/100068/0608/
 *           migrating-from-armasm-to-the-armclang-integrated-assembler/sections
 *  
 * - GNU assembler 로 찾아야하는지 ARM assembler에대한 specific인지
 *   확인해가면서 볼필요있음.
 *
 * - links:
 *   1. https://sourceware.org/binutils/docs/as/Section.html
 */

#define __HEAD		.section	".head.text","ax"
#define __INIT		.section	".init.text","ax"
#define __FINIT		.previous

#define __INITDATA	.section	".init.data","aw",%progbits
#define __INITRODATA	.section	".init.rodata","a",%progbits
#define __FINITDATA	.previous

#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"

/* silence warnings when references are OK */
#define __REF            .section       ".ref.text", "ax"
#define __REFDATA        .section       ".ref.data", "aw"
#define __REFCONST       .section       ".ref.rodata", "a"

#ifndef __ASSEMBLY__
/*
 * Used for initialization calls..
 */
typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);

#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
typedef int initcall_entry_t;

static inline initcall_t initcall_from_entry(initcall_entry_t *entry)
{
	return offset_to_ptr(entry);
}
#else
typedef initcall_t initcall_entry_t;

static inline initcall_t initcall_from_entry(initcall_entry_t *entry)
{
	return *entry;
}
#endif

extern initcall_entry_t __con_initcall_start[], __con_initcall_end[];

/* Used for contructor calls. */
typedef void (*ctor_fn_t)(void);

struct file_system_type;

/* Defined in init/main.c */
extern int do_one_initcall(initcall_t fn);
extern char __initdata boot_command_line[];
extern char *saved_command_line;
extern unsigned int reset_devices;

/* used by init/main.c */
void setup_arch(char **);
void prepare_namespace(void);
void __init init_rootfs(void);
extern struct file_system_type rootfs_fs_type;

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
extern bool rodata_enabled;
#endif
#ifdef CONFIG_STRICT_KERNEL_RWX
void mark_rodata_ro(void);
#endif

extern void (*late_time_init)(void);

extern bool initcall_debug;

#endif
  
#ifndef MODULE

#ifndef __ASSEMBLY__

/*
 * initcalls are now grouped by functionality into separate
 * subsections. Ordering inside the subsections is determined
 * by link order. 
 * For backwards compatibility, initcall() puts the call in 
 * the device init subsection.
 *
 * The `id' arg to __define_initcall() is needed so that multiple initcalls
 * can point at the same handler without causing duplicate-symbol build errors.
 *
 * Initcalls are run by placing pointers in initcall sections that the
 * kernel iterates at runtime. The linker can do dead code / data elimination
 * and remove that completely, so the initcall sections have to be marked
 * as KEEP() in the linker script.
 */

#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
#define ___define_initcall(fn, id, __sec)			\
	__ADDRESSABLE(fn)					\
	asm(".section	\"" #__sec ".init\", \"a\"	\n"	\
	"__initcall_" #fn #id ":			\n"	\
	    ".long	" #fn " - .			\n"	\
	    ".previous					\n");
#else
#define ___define_initcall(fn, id, __sec) \
	static initcall_t __initcall_##fn##id __used \
		__attribute__((__section__(#__sec ".init"))) = fn;
#endif

#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)

/*
 * Early initcalls run before initializing SMP.
 *
 * Only for built-in code, not modules.
 */
#define early_initcall(fn)		__define_initcall(fn, early)

/*
 * A "pure" initcall has no dependencies on anything else, and purely
 * initializes variables that couldn't be statically initialized.
 *
 * This only exists for built-in code, not for modules.
 * Keep main.c:initcall_level_names[] in sync.
 */
#define pure_initcall(fn)		__define_initcall(fn, 0)

#define core_initcall(fn)		__define_initcall(fn, 1)
#define core_initcall_sync(fn)		__define_initcall(fn, 1s)
#define postcore_initcall(fn)		__define_initcall(fn, 2)
#define postcore_initcall_sync(fn)	__define_initcall(fn, 2s)
#define arch_initcall(fn)		__define_initcall(fn, 3)
#define arch_initcall_sync(fn)		__define_initcall(fn, 3s)
#define subsys_initcall(fn)		__define_initcall(fn, 4)
#define subsys_initcall_sync(fn)	__define_initcall(fn, 4s)
#define fs_initcall(fn)			__define_initcall(fn, 5)
#define fs_initcall_sync(fn)		__define_initcall(fn, 5s)
#define rootfs_initcall(fn)		__define_initcall(fn, rootfs)
#define device_initcall(fn)		__define_initcall(fn, 6)
#define device_initcall_sync(fn)	__define_initcall(fn, 6s)
#define late_initcall(fn)		__define_initcall(fn, 7)
#define late_initcall_sync(fn)		__define_initcall(fn, 7s)

#define __initcall(fn) device_initcall(fn)

#define __exitcall(fn)						\
	static exitcall_t __exitcall_##fn __exit_call = fn

#define console_initcall(fn)	___define_initcall(fn,, .con_initcall)

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

/*
 * Only for really core code.  See moduleparam.h for the normal way.
 *
 * Force the alignment so the compiler doesn't space elements of the
 * obs_kernel_param "array" too far apart in .init.setup.
 */
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(".init.setup")				\
		__attribute__((aligned((sizeof(long)))))		\
		= { __setup_str_##unique_id, fn, early }

#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)

/*
 * NOTE: fn is as per module_param, not __setup!
 * Emits warning if fn returns non-zero.
 */
#define early_param(str, fn)						\
	__setup_param(str, fn, fn, 1)

#define early_param_on_off(str_on, str_off, var, config)		\
									\
	int var = IS_ENABLED(config);					\
									\
	static int __init parse_##var##_on(char *arg)			\
	{								\
		var = 1;						\
		return 0;						\
	}								\
	__setup_param(str_on, parse_##var##_on, parse_##var##_on, 1);	\
									\
	static int __init parse_##var##_off(char *arg)			\
	{								\
		var = 0;						\
		return 0;						\
	}								\
	__setup_param(str_off, parse_##var##_off, parse_##var##_off, 1)

/* Relies on boot_command_line being set */
void __init parse_early_param(void);
void __init parse_early_options(char *cmdline);
#endif /* __ASSEMBLY__ */

#else /* MODULE */

#define __setup_param(str, unique_id, fn)	/* nothing */
#define __setup(str, func) 			/* nothing */
#endif

/* Data marked not to be saved by software suspend */
#define __nosavedata __section(".data..nosave")

#ifdef MODULE
#define __exit_p(x) x
#else
#define __exit_p(x) NULL
#endif

#endif /* _LINUX_INIT_H */
