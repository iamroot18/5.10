/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_KERNEL_H
#define _UAPI_LINUX_KERNEL_H

#include <linux/sysinfo.h>

/*
 * 'kernel.h' contains some often-used function prototypes etc
 */
/*
 * IAMROOT, 2021.10.09: 
 * __ALIGN_KERNEL(x, a):
 *   x 값을 a 정렬 단위로 round up 한다. (a는 2의 승수 단위만 가능하다)
 *   예) x=0x1234, a=0x1000
 *       -> (0x1234 + 0xfff) & ~0xfff
 *                             (0xffff_ffff_ffff_f000)
 */
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#endif /* _UAPI_LINUX_KERNEL_H */
