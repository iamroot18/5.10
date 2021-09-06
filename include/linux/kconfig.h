/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_KCONFIG_H
#define __LINUX_KCONFIG_H

/* CONFIG_CC_VERSION_TEXT (Do not delete this comment. See help in Kconfig) */

#include <generated/autoconf.h>

#ifdef CONFIG_CPU_BIG_ENDIAN
#define __BIG_ENDIAN 4321
#else
#define __LITTLE_ENDIAN 1234
#endif

#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val

/*
 * The use of "&&" / "||" is limited in certain expressions.
 * The following enable to calculate "and" / "or" with macro expansion only.
 */
#define __and(x, y)			___and(x, y)
#define ___and(x, y)			____and(__ARG_PLACEHOLDER_##x, y)
#define ____and(arg1_or_junk, y)	__take_second_arg(arg1_or_junk y, 0)

#define __or(x, y)			___or(x, y)
#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)
#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)

/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */

/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
#define __is_defined(x)			___is_defined(x)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)

/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
#define IS_BUILTIN(option) __is_defined(option)

/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
#define IS_MODULE(option) __is_defined(option##_MODULE)

/*
 * IS_REACHABLE(CONFIG_FOO) evaluates to 1 if the currently compiled
 * code can call a function defined in code compiled based on CONFIG_FOO.
 * This is similar to IS_ENABLED(), but returns false when invoked from
 * built-in code when CONFIG_FOO is set to 'm'.
 */
#define IS_REACHABLE(option) __or(IS_BUILTIN(option), \
				__and(IS_MODULE(option), __is_defined(MODULE)))

/*
 * IAMROOT, 2021.09.05:
 *
 * - .config파일에 의해 #define CONFIG_XXX, CONFIG_XXX_MODULE이 만들어지는 과정
 *
 *   .config파일에 다음과 같이 set됬다고한다.
 *
 *   .CONFIG_ABC=y
 *
 *   이렇게 되고나서 컴파일을 하게 되면 autoconf.h에 다음과 같이 정의가 된다.
 *
 *   #define CONFIG_ABC 1
 *
 *   만약 .CONFIG_ABC=m 이라고 .config에 정의가 됬다면 뒤에 _MODULE이 붙은 형태로
 *   만들어진다.
 *
 *   #define CONFING_ABC_MODULE 1
 *
 *   이런 이유로 IS_MODULE에서 해당 config가 module로 되있는지에 대해 검사를
 *   하기위해 _MODULE을 뒤에 붙이는거다.
 *   만약 .config에 .CONFIG_ABC가 존재하지 않거나
 *
 *   # CONFIG_ABC is not set
 *
 *   이라고 .config에 주석처리되어 있으면 #define은 생기지 않는다.
 *
 * __is_defined:
 *
 *   - IS_ENABLE이 IS_BUILTIN, IS_MODULE과 관계가 있고 IS_BUILTIN, IS_MODULE은
 *   __is_defined과 관계가 있으니 __is_defined부터 살펴본다.
 *
 *   __is_defined(val) 에서 마지막까지 매크로를 풀어보면 다음과 같다.
 *
 *   __take_second_arg(__ARG_PLACEHOLDER_##val 1, 0)
 *
 *   여기서 val은 CONFIG_XXX와 같은것이 오게되는데 CONFIG_XXX는 존재를 안하거나
 *   1인 경우밖에 없으므로 다음 두가지로 정리가 된다.
 *
 *   - CONFIG가 존재 : __take_second_arg(__ARG_PLACEHOLDER_1, 0)
 *   존재하는 경우엔 __ARG_PLACEHOLDER_1 매크로에 의해 다음과 같이 치환된다.
 *
 *   __take_second_arg(0, 1, 0)
 *
 *   결국 __take_second_arg를 살펴보면 두번째 인자를 얻어오므로 1이 return 된다.
 *
 *   - CONFIG가 없음 : __take_second_arg(__ARG_PLACEHOLDER_, 0)
 *   __take_second_arg(__ignored, val, ...) 에서 3번째 인자가 가변인자를 취하고
 *   있는데 이 것때문에 __take_second_arg(__ARG_PLACEHOLDER_ 1, 0)와 같이
 *   정의 되지 않은 매크로가 존재하면 마치 없는 것처럼 취급되어
 *   __take_second_arg(1, 0)의 형태로 컴파일러가 인식을 하게 되고 두번째 인자는
 *   0으로 return되는것이다.
 *
 * __or:
 *  - __is_defined의 원리와 같다. 다만 맨마지막 __take_second_arg의 두번째 인자가
 *  __is_defined에서는 0으로 고정이였지만 __or에서는 2번째 인자값에 따라 바뀐다.
 *  결국에 __or에서도 첫번째 인자가 1이면 __take_second_arg첫번째 인자가
 *  __ARG_PLACEHOLDER_1로 치환되므로 1이되고,
 *  두번째 인자가 1이면, 마지막 __take_second_arg에서 두번째 인자로 return되는것이
 *  결국 __or의 두번째 인자가 return되므로 1이 되는것이다.
 */

/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))

#endif /* __LINUX_KCONFIG_H */
