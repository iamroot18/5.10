/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/assembler.h, arch/arm/mm/proc-macros.S
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASSEMBLY__
#error "Only include this from assembly code"
#endif

#ifndef __ASM_ASSEMBLER_H
#define __ASM_ASSEMBLER_H

#include <asm-generic/export.h>

#include <asm/asm-offsets.h>
#include <asm/cpufeature.h>
#include <asm/cputype.h>
#include <asm/debug-monitors.h>
#include <asm/page.h>
#include <asm/pgtable-hwdef.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>
/*
 * IAMROOT, 2021.10.30:
 * - 원래 있던 daif에 대한 flag를 읽어온후 disable 시킨다.
 * - restore_daif와 한쌍이 된다.
 */
	.macro save_and_disable_daif, flags
	mrs	\flags, daif
	msr	daifset, #0xf
	.endm

	.macro disable_daif
	msr	daifset, #0xf
	.endm

	.macro enable_daif
	msr	daifclr, #0xf
	.endm
/*
 * IAMROOT, 2021.10.30:
 * - 저장해놓은 flag를 다시 복귀 시킨다.
 * - save_and_disable_daif와 한쌍이 된다.
 */
	.macro	restore_daif, flags:req
	msr	daif, \flags
	.endm

	/* IRQ is the lowest priority flag, unconditionally unmask the rest. */
	.macro enable_da_f
	msr	daifclr, #(8 | 4 | 1)
	.endm

/*
 * Save/restore interrupts.
 */
	.macro	save_and_disable_irq, flags
	mrs	\flags, daif
	msr	daifset, #2
	.endm

	.macro	restore_irq, flags
	msr	daif, \flags
	.endm

	.macro	enable_dbg
	msr	daifclr, #8
	.endm

	.macro	disable_step_tsk, flgs, tmp
	tbz	\flgs, #TIF_SINGLESTEP, 9990f
	mrs	\tmp, mdscr_el1
	bic	\tmp, \tmp, #DBG_MDSCR_SS
	msr	mdscr_el1, \tmp
	isb	// Synchronise with enable_dbg
9990:
	.endm

	/* call with daif masked */
	.macro	enable_step_tsk, flgs, tmp
	tbz	\flgs, #TIF_SINGLESTEP, 9990f
	mrs	\tmp, mdscr_el1
	orr	\tmp, \tmp, #DBG_MDSCR_SS
	msr	mdscr_el1, \tmp
9990:
	.endm

/*
 * RAS Error Synchronization barrier
 */
	.macro  esb
#ifdef CONFIG_ARM64_RAS_EXTN
	hint    #16
#else
	nop
#endif
	.endm

/*
 * Value prediction barrier
 */
	.macro	csdb
	hint	#20
	.endm

/*
 * Speculation barrier
 */
	.macro	sb
alternative_if_not ARM64_HAS_SB
	dsb	nsh
	isb
alternative_else
	SB_BARRIER_INSN
	nop
alternative_endif
	.endm

/*
 * NOP sequence
 */
	.macro	nops, num
	.rept	\num
	nop
	.endr
	.endm

/*
 * Emit an entry into the exception table
 */
	.macro		_asm_extable, from, to
	.pushsection	__ex_table, "a"
	.align		3
	.long		(\from - .), (\to - .)
	.popsection
	.endm

#define USER(l, x...)				\
9999:	x;					\
	_asm_extable	9999b, l

/*
 * Register aliases.
 */
lr	.req	x30		// link register

/*
 * Vector entry
 */
	 .macro	ventry	label
	.align	7
	b	\label
	.endm

/*
 * Select code when configured for BE.
 */
#ifdef CONFIG_CPU_BIG_ENDIAN
#define CPU_BE(code...) code
#else
#define CPU_BE(code...)
#endif

/*
 * Select code when configured for LE.
 */
#ifdef CONFIG_CPU_BIG_ENDIAN
#define CPU_LE(code...)
#else
#define CPU_LE(code...) code
#endif

/*
 * Define a macro that constructs a 64-bit value by concatenating two
 * 32-bit registers. Note that on big endian systems the order of the
 * registers is swapped.
 */
#ifndef CONFIG_CPU_BIG_ENDIAN
	.macro	regs_to_64, rd, lbits, hbits
#else
	.macro	regs_to_64, rd, hbits, lbits
#endif
	orr	\rd, \lbits, \hbits, lsl #32
	.endm

/*
 * Pseudo-ops for PC-relative adr/ldr/str <reg>, <symbol> where
 * <symbol> is within the range +/- 4 GB of the PC.
 */
	/*
	 * @dst: destination register (64 bit wide)
	 * @sym: name of the symbol
	 */
	.macro	adr_l, dst, sym
	adrp	\dst, \sym
	add	\dst, \dst, :lo12:\sym
	.endm

	/*
	 * @dst: destination register (32 or 64 bit wide)
	 * @sym: name of the symbol
	 * @tmp: optional 64-bit scratch register to be used if <dst> is a
	 *       32-bit wide register, in which case it cannot be used to hold
	 *       the address
	 */
	.macro	ldr_l, dst, sym, tmp=
	.ifb	\tmp
	adrp	\dst, \sym
	ldr	\dst, [\dst, :lo12:\sym]
	.else
	adrp	\tmp, \sym
	ldr	\dst, [\tmp, :lo12:\sym]
	.endif
	.endm

	/*
	 * @src: source register (32 or 64 bit wide)
	 * @sym: name of the symbol
	 * @tmp: mandatory 64-bit scratch register to calculate the address
	 *       while <src> needs to be preserved.
	 */
/*
 * IAMROOT, 2021.08.14: 
 * - *sym <- src의 주소
 *
 * - 예) str_l   x4, idmap_ptrs_per_pgd, x5
 *         adrp x5, idmap_ptrs_per_pgd
 *         str  x4, [x5, :lo12:idmap_ptrs_per_pgd]
 *
 *         idmpa_ptrs_per_pgd <- x4 값을 저장
 */
	.macro	str_l, src, sym, tmp
	adrp	\tmp, \sym
	str	\src, [\tmp, :lo12:\sym]
	.endm

	/*
	 * @dst: destination register
	 */
#if defined(__KVM_NVHE_HYPERVISOR__) || defined(__KVM_VHE_HYPERVISOR__)
	.macro	this_cpu_offset, dst
	mrs	\dst, tpidr_el2
	.endm
#else
	.macro	this_cpu_offset, dst
alternative_if_not ARM64_HAS_VIRT_HOST_EXTN
	mrs	\dst, tpidr_el1
alternative_else
	mrs	\dst, tpidr_el2
alternative_endif
	.endm
#endif

	/*
	 * @dst: Result of per_cpu(sym, smp_processor_id()) (can be SP)
	 * @sym: The name of the per-cpu variable
	 * @tmp: scratch register
	 */
	.macro adr_this_cpu, dst, sym, tmp
	adrp	\tmp, \sym
	add	\dst, \tmp, #:lo12:\sym
	this_cpu_offset \tmp
	add	\dst, \dst, \tmp
	.endm

	/*
	 * @dst: Result of READ_ONCE(per_cpu(sym, smp_processor_id()))
	 * @sym: The name of the per-cpu variable
	 * @tmp: scratch register
	 */
	.macro ldr_this_cpu dst, sym, tmp
	adr_l	\dst, \sym
	this_cpu_offset \tmp
	ldr	\dst, [\dst, \tmp]
	.endm

/*
 * vma_vm_mm - get mm pointer from vma pointer (vma->vm_mm)
 */
	.macro	vma_vm_mm, rd, rn
	ldr	\rd, [\rn, #VMA_VM_MM]
	.endm

/*
 * read_ctr - read CTR_EL0. If the system has mismatched register fields,
 * provide the system wide safe value from arm64_ftr_reg_ctrel0.sys_val
 */
	.macro	read_ctr, reg
alternative_if_not ARM64_MISMATCHED_CACHE_TYPE
/* IAMROOT, 2021.07.17:
 * ctr_el0: Cache Type Register
 */
	mrs	\reg, ctr_el0			// read CTR
/* IAMROOT, 2021.07.17: 1 cycle 휴식 */
	nop
alternative_else
/* IAMROOT, 2021.07.17:
 * Cache Type mismatched 라면?
 */
	ldr_l	\reg, arm64_ftr_reg_ctrel0 + ARM64_FTR_SYSVAL
alternative_endif
	.endm


/*
 * raw_dcache_line_size - get the minimum D-cache line size on this CPU
 * from the CTR register.
 */
	.macro	raw_dcache_line_size, reg, tmp
	mrs	\tmp, ctr_el0			// read CTR
	ubfm	\tmp, \tmp, #16, #19		// cache line size encoding
	mov	\reg, #4			// bytes per word
	lsl	\reg, \reg, \tmp		// actual cache line size
	.endm

/*
 * dcache_line_size - get the safe D-cache line size across all CPUs
 */
/* IAMROOT, 2021.07.17:
 * - Cache Type Register에서 최소 데이터 캐시 라인을 바이트로 알아오기.
 *   reg = 4 * 2^(CTR_EL0.DminLine)
 *   예) reg = 4 * 2^4 = 64 bytes
 */
	.macro	dcache_line_size, reg, tmp
	read_ctr	\tmp
	ubfm		\tmp, \tmp, #16, #19	// cache line size encoding
	mov		\reg, #4		// bytes per word
	lsl		\reg, \reg, \tmp	// actual cache line size
	.endm

/*
 * raw_icache_line_size - get the minimum I-cache line size on this CPU
 * from the CTR register.
 */
	.macro	raw_icache_line_size, reg, tmp
	mrs	\tmp, ctr_el0			// read CTR
	and	\tmp, \tmp, #0xf		// cache line size encoding
	mov	\reg, #4			// bytes per word
	lsl	\reg, \reg, \tmp		// actual cache line size
	.endm

/*
 * icache_line_size - get the safe I-cache line size across all CPUs
 */
	.macro	icache_line_size, reg, tmp
	read_ctr	\tmp
	and		\tmp, \tmp, #0xf	// cache line size encoding
	mov		\reg, #4		// bytes per word
	lsl		\reg, \reg, \tmp	// actual cache line size
	.endm

/*
 * tcr_set_t0sz - update TCR.T0SZ so that we can load the ID map
 */
	.macro	tcr_set_t0sz, valreg, t0sz
	bfi	\valreg, \t0sz, #TCR_T0SZ_OFFSET, #TCR_TxSZ_WIDTH
	.endm

/*
 * tcr_set_t1sz - update TCR.T1SZ
 */
	.macro	tcr_set_t1sz, valreg, t1sz
	bfi	\valreg, \t1sz, #TCR_T1SZ_OFFSET, #TCR_TxSZ_WIDTH
	.endm

/*
 * tcr_compute_pa_size - set TCR.(I)PS to the highest supported
 * ID_AA64MMFR0_EL1.PARange value
 *
 *	tcr:		register with the TCR_ELx value to be updated
 *	pos:		IPS or PS bitfield position
 *	tmp{0,1}:	temporary registers
 */
/*
 * IAMROOT, 2021.08.28:
 * tmp0: feature 레지스터에서 읽어온 PARange 값.
 * tmp1: 커널이 설정한 MAX PARange 값.
 * tmp0와 tmp1을 unsigned로 비교해서
 * tmp0가 tmp1보다 크면 tmp0 = tmp1을 해준다.
 */
	.macro	tcr_compute_pa_size, tcr, pos, tmp0, tmp1
	mrs	\tmp0, ID_AA64MMFR0_EL1
	// Narrow PARange to fit the PS field in TCR_ELx
	ubfx	\tmp0, \tmp0, #ID_AA64MMFR0_PARANGE_SHIFT, #3
	mov	\tmp1, #ID_AA64MMFR0_PARANGE_MAX
	cmp	\tmp0, \tmp1
	csel	\tmp0, \tmp1, \tmp0, hi
	bfi	\tcr, \tmp0, \pos, #3
	.endm

/*
 * Macro to perform a data cache maintenance for the interval
 * [kaddr, kaddr + size)
 *
 * 	op:		operation passed to dc instruction
 * 	domain:		domain used in dsb instruciton
 * 	kaddr:		starting virtual address of the region
 * 	size:		size of the region
 * 	Corrupts:	kaddr, size, tmp1, tmp2
 */
	.macro __dcache_op_workaround_clean_cache, op, kaddr
alternative_if_not ARM64_WORKAROUND_CLEAN_CACHE
	dc	\op, \kaddr
alternative_else
	dc	civac, \kaddr
alternative_endif
	.endm

/*
 * IAMROOT, 2021.09.07:
 * .ifc:
 *  - 참고 https://developer.arm.com/documentation/100067/0612/armclang-Integrated-Assembler/Conditional-assembly-directives
 *  - .ifc에 맞는 조건에 따라서 assembly code가 생성된다.
 *  예를들어 
 *  dcache_by_line_op civac, sy, x0, x1, x2, x3
 *
 *  위와 같은 code가 있다면 .ifc 자리에는
 *  dc civac, \kaddr 
 *  명령어가 매크로 자리로 들어갈것이다.
 *
 * - kaddr(start address)부터 size만큼 dc 명령어를 수행후 dsb sy까지 수행한다.
 */
	.macro dcache_by_line_op op, domain, kaddr, size, tmp1, tmp2
	dcache_line_size \tmp1, \tmp2
	add	\size, \kaddr, \size
	sub	\tmp2, \tmp1, #1
	bic	\kaddr, \kaddr, \tmp2
9998:
	.ifc	\op, cvau
	__dcache_op_workaround_clean_cache \op, \kaddr
	.else
	.ifc	\op, cvac
	__dcache_op_workaround_clean_cache \op, \kaddr
	.else
	.ifc	\op, cvap
	sys	3, c7, c12, 1, \kaddr	// dc cvap
	.else
	.ifc	\op, cvadp
	sys	3, c7, c13, 1, \kaddr	// dc cvadp
	.else
	dc	\op, \kaddr
	.endif
	.endif
	.endif
	.endif
	add	\kaddr, \kaddr, \tmp1
	cmp	\kaddr, \size
	b.lo	9998b
	dsb	\domain
	.endm

/*
 * Macro to perform an instruction cache maintenance for the interval
 * [start, end)
 *
 * 	start, end:	virtual addresses describing the region
 *	label:		A label to branch to on user fault.
 * 	Corrupts:	tmp1, tmp2
 */
	.macro invalidate_icache_by_line start, end, tmp1, tmp2, label
	icache_line_size \tmp1, \tmp2
	sub	\tmp2, \tmp1, #1
	bic	\tmp2, \start, \tmp2
9997:
USER(\label, ic	ivau, \tmp2)			// invalidate I line PoU
	add	\tmp2, \tmp2, \tmp1
	cmp	\tmp2, \end
	b.lo	9997b
	dsb	ish
	isb
	.endm
/*
 * IAMROOT, 2021.08.21:
 * - id_aa64dfr0_el1.PMUVer:
 *     PMUVer가 0이면 즉, PME (Performance Monitor Extension) 가 not implemented 이면 아무것도 안함.
 *     PMUVer가 0이 아니면 즉, PMUv3가 implemented 되있으면 pmuserenr_el0를 0으로 초기화한다.
 *     pmuserenr_el0를 0으로 초기화 한다는 말은 EL0가 PM 관련 레지스터 접근시 trap 하겠다는 뜻이다. (Disable PMU).
 */
/*
 * reset_pmuserenr_el0 - reset PMUSERENR_EL0 if PMUv3 present
 */
	.macro	reset_pmuserenr_el0, tmpreg
	mrs	\tmpreg, id_aa64dfr0_el1
	sbfx	\tmpreg, \tmpreg, #ID_AA64DFR0_PMUVER_SHIFT, #4
	cmp	\tmpreg, #1			// Skip if no PMU present
	b.lt	9000f
	msr	pmuserenr_el0, xzr		// Disable PMU access from EL0
9000:
	.endm

/*
 * IAMROOT, 2021.08.28:
 * - id_aa64dfr0_el1.AMU:
 *     AMU가 0이면 즉, AME (Activity Monitors Extension) 가 not implemented 이면 아무것도 안함.
 *     AMU가 0이 아니면 즉, AMU가 implemented 되있으면 amuserenr_el0를 0으로 초기화한다
 *     amuserenr_el0를 0으로 초기화 한다는 말은 EL0가 AM 관련 레지스터 접근시 trap 하겠다는 뜻이다. (Disable AMU).
 */
/*
 * reset_amuserenr_el0 - reset AMUSERENR_EL0 if AMUv1 present
 */
	.macro	reset_amuserenr_el0, tmpreg
	mrs	\tmpreg, id_aa64pfr0_el1	// Check ID_AA64PFR0_EL1
	ubfx	\tmpreg, \tmpreg, #ID_AA64PFR0_AMU_SHIFT, #4
	cbz	\tmpreg, .Lskip_\@		// Skip if no AMU present
	msr_s	SYS_AMUSERENR_EL0, xzr		// Disable AMU access from EL0
.Lskip_\@:
	.endm
/*
 * copy_page - copy src to dest using temp registers t1-t8
 */
	.macro copy_page dest:req src:req t1:req t2:req t3:req t4:req t5:req t6:req t7:req t8:req
9998:	ldp	\t1, \t2, [\src]
	ldp	\t3, \t4, [\src, #16]
	ldp	\t5, \t6, [\src, #32]
	ldp	\t7, \t8, [\src, #48]
	add	\src, \src, #64
	stnp	\t1, \t2, [\dest]
	stnp	\t3, \t4, [\dest, #16]
	stnp	\t5, \t6, [\dest, #32]
	stnp	\t7, \t8, [\dest, #48]
	add	\dest, \dest, #64
	tst	\src, #(PAGE_SIZE - 1)
	b.ne	9998b
	.endm

/*
 * Annotate a function as being unsuitable for kprobes.
 */
#ifdef CONFIG_KPROBES
#define NOKPROBE(x)				\
	.pushsection "_kprobe_blacklist", "aw";	\
	.quad	x;				\
	.popsection;
#else
#define NOKPROBE(x)
#endif

#ifdef CONFIG_KASAN
#define EXPORT_SYMBOL_NOKASAN(name)
#else
#define EXPORT_SYMBOL_NOKASAN(name)	EXPORT_SYMBOL(name)
#endif

	/*
	 * Emit a 64-bit absolute little endian symbol reference in a way that
	 * ensures that it will be resolved at build time, even when building a
	 * PIE binary. This requires cooperation from the linker script, which
	 * must emit the lo32/hi32 halves individually.
	 */
	.macro	le64sym, sym
	.long	\sym\()_lo32
	.long	\sym\()_hi32
	.endm

	/*
	 * mov_q - move an immediate constant into a 64-bit register using
	 *         between 2 and 4 movz/movk instructions (depending on the
	 *         magnitude and sign of the operand)
	 */


	/*
	 * IAMROOT, 2021.07.24: 
	 * reg 에 val 값을 대입한다. 단, 64 비트 레지스터이며,
	 * val 의 값은 상수여야 한다.
	 */
	.macro	mov_q, reg, val
	.if (((\val) >> 31) == 0 || ((\val) >> 31) == 0x1ffffffff)
		movz	\reg, :abs_g1_s:\val
		/*
		 *  IAMROOT, 2021.07.24:
		 *  movz reg, shift, val
		 *  
		 *  abs_g1_s: Absolute, signed, [31:16] range
		 *  https://www.keil.com/support/man/docs/armclang_ref/armclang_ref_zvb1510926525383.htm
		 */
	.else
		.if (((\val) >> 47) == 0 || ((\val) >> 47) == 0x1ffff)
			movz	\reg, :abs_g2_s:\val
		.else
			movz	\reg, :abs_g3:\val
			movk	\reg, :abs_g2_nc:\val
		.endif

		movk	\reg, :abs_g1_nc:\val
	.endif

	movk	\reg, :abs_g0_nc:\val
	.endm

/*
 * Return the current task_struct.
 */
	.macro	get_current_task, rd
	mrs	\rd, sp_el0
	.endm

/*
 * IAMROOT, 2021.08.28:
 * ARM Ref : D5.3.1 VMSAv8-64 translation table level -1, level 0, level 1, and level 2 descriptor formats
 * - kernel이 VA 52bit인 상태에서 Arch가 48bit만을 지원하는 경우
 *   pgd table 위치를 offset(0x1e00)만큼 더한다.
 *
 * ---
 *
 * kernel, arch 둘다 VA bit가 48이거나 52인 경우 문제가 없는데,
 * kernel만 52일 경우 다음과 같은 문제가 발생한다.
 *
 * 주소 0x0000_0000_0000을 접근한다고 가정햇을때
 * pgd_index를 구해보면 (42bit(PGDIR_SHIFT) shift시키면)
 *
 * kernel : pgd_index(0xffff_0000_0000_0000) = 0x3c0
 * user   : pgd_index(0x0000_0000_0000_0000) = 0
 *
 * user 영역은 변화가 없지만 kernel영역은 변화가 생긴다.
 * (user, kernel 둘다 같은 VA bit를 사용한다면 전부 0으로 나온다.)
 *
 * kernel에서는 user 영역이든 kenrel 영역이든 pgd_index를 사용하여
 * pgd를 접근하는데 해당 환경일때만 다른 pgd_index가 발생한다.
 *
 * 그래서 el1에서만 offset값인 0x3c0에 entry크기인 8만큼을
 * 곱한 0x1e00를 보정해주는것이다.
 *
 * runtime시 arch에 따라, user냐 kernel에 따라 보정해줄수도 있지만
 * kernel은 가능한한 compile time에 이런 연산을 끝내고 runtime시에의
 * 연산을 최소화하는 정책을 사용하므로 이러한 용법이 들어간거라고 볼수있다.
 *
 * ---
 *  ARM Ref에는 해당 bit들이 RES0로 써야된다고 나와있긴하지만 Ref에 잘못
 *  써져있다고 생각이 된다고 일단 의견을 모은 상태.
 */
/*
 * Offset ttbr1 to allow for 48-bit kernel VAs set with 52-bit PTRS_PER_PGD.
 * orr is used as it can cover the immediate value (and is idempotent).
 * In future this may be nop'ed out when dealing with 52-bit kernel VAs.
 * 	ttbr: Value of ttbr to set, modified.
 */
	.macro	offset_ttbr1, ttbr, tmp
#ifdef CONFIG_ARM64_VA_BITS_52
	mrs_s	\tmp, SYS_ID_AA64MMFR2_EL1
	and	\tmp, \tmp, #(0xf << ID_AA64MMFR2_LVA_SHIFT)
	cbnz	\tmp, .Lskipoffs_\@
	orr	\ttbr, \ttbr, #TTBR1_BADDR_4852_OFFSET
.Lskipoffs_\@ :
#endif
	.endm

/*
 * Perform the reverse of offset_ttbr1.
 * bic is used as it can cover the immediate value and, in future, won't need
 * to be nop'ed out when dealing with 52-bit kernel VAs.
 */
	.macro	restore_ttbr1, ttbr
#ifdef CONFIG_ARM64_VA_BITS_52
	bic	\ttbr, \ttbr, #TTBR1_BADDR_4852_OFFSET
#endif
	.endm

/*
 * Arrange a physical address in a TTBR register, taking care of 52-bit
 * addresses.
 *
 * 	phys:	physical address, preserved
 * 	ttbr:	returns the TTBR value
 */
	.macro	phys_to_ttbr, ttbr, phys
#ifdef CONFIG_ARM64_PA_BITS_52
	orr	\ttbr, \phys, \phys, lsr #46
	and	\ttbr, \ttbr, #TTBR_BADDR_MASK_52
#else
	mov	\ttbr, \phys
#endif
	.endm
/*
 * IAMROOT, 2021.08.21:
 *
 * ARM Ref p2448 Page, 64KB granule 참고.
 * ---
 * - CONFIG_ARM64_PA_BITS_52인 경우에는
 * pte = phys | (phys >> 36)
 * pte &= PTE_ADDR_MASK;
 *
 * ---
 *
 * (phys | phys >> 36) & PTE_ADDR_MASK
 * 
 * ---
 *
 * 52 bit system 은 PA 중 [51:16] 이 유용한 주소공간이고,
 * 이를 48bit system 처럼 [47:12] 로 사용하기 위해
 * [51:48]을 >> 36 한 뒤 [15:12] 으로 만들어 [47:12] 만큼 Masking하여 사용
 *
 * ---
 *
 * 52bit 인경우 page는 64k aligned 되있으므로
 * [51:16] 까지만 사용중이고 Ref menual에 보면
 *
 * If ARMv8.2-LPA is implemented, bits[15:12] are bits[51:48] and bits[47:16] are
 * bits[47:16] of the output address for a page of memory.
 * 
 * 이라는 내용이 있다. 즉 [51:16]을 사용하고 있는데 mapping은 [47:12]를 써야되므로
 * 47의 뒤인 [51:48]을 [16:12]로 이동시키기 위함이다.
 */

	.macro	phys_to_pte, pte, phys
#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * We assume \phys is 64K aligned and this is guaranteed by only
	 * supporting this configuration with 64K pages.
	 */
	orr	\pte, \phys, \phys, lsr #36
	and	\pte, \pte, #PTE_ADDR_MASK
#else
	mov	\pte, \phys
#endif
	.endm

	.macro	pte_to_phys, phys, pte
#ifdef CONFIG_ARM64_PA_BITS_52
	ubfiz	\phys, \pte, #(48 - 16 - 12), #16
	bfxil	\phys, \pte, #16, #32
	lsl	\phys, \phys, #16
#else
	and	\phys, \pte, #PTE_ADDR_MASK
#endif
	.endm

/*
 * tcr_clear_errata_bits - Clear TCR bits that trigger an errata on this CPU.
 */
/*
 * IAMROOT, 2021.08.25:
 * - ID register에서 Fujitsu 라는게 맞다면 TCR_NFD1, TCR_NFD0 bit 를 clear한다.
 */
	.macro	tcr_clear_errata_bits, tcr, tmp1, tmp2
#ifdef CONFIG_FUJITSU_ERRATUM_010001
	mrs	\tmp1, midr_el1

	mov_q	\tmp2, MIDR_FUJITSU_ERRATUM_010001_MASK
	and	\tmp1, \tmp1, \tmp2
	mov_q	\tmp2, MIDR_FUJITSU_ERRATUM_010001
	cmp	\tmp1, \tmp2
	b.ne	10f

	mov_q	\tmp2, TCR_CLEAR_FUJITSU_ERRATUM_010001
	bic	\tcr, \tcr, \tmp2
10:
#endif /* CONFIG_FUJITSU_ERRATUM_010001 */
	.endm

/**
 * Errata workaround prior to disable MMU. Insert an ISB immediately prior
 * to executing the MSR that will change SCTLR_ELn[M] from a value of 1 to 0.
 */
	.macro pre_disable_mmu_workaround
#ifdef CONFIG_QCOM_FALKOR_ERRATUM_E1041
	isb
#endif
	.endm

	/*
	 * frame_push - Push @regcount callee saved registers to the stack,
	 *              starting at x19, as well as x29/x30, and set x29 to
	 *              the new value of sp. Add @extra bytes of stack space
	 *              for locals.
	 */
	.macro		frame_push, regcount:req, extra
	__frame		st, \regcount, \extra
	.endm

	/*
	 * frame_pop  - Pop the callee saved registers from the stack that were
	 *              pushed in the most recent call to frame_push, as well
	 *              as x29/x30 and any extra stack space that may have been
	 *              allocated.
	 */
	.macro		frame_pop
	__frame		ld
	.endm

	.macro		__frame_regs, reg1, reg2, op, num
	.if		.Lframe_regcount == \num
	\op\()r		\reg1, [sp, #(\num + 1) * 8]
	.elseif		.Lframe_regcount > \num
	\op\()p		\reg1, \reg2, [sp, #(\num + 1) * 8]
	.endif
	.endm

	.macro		__frame, op, regcount, extra=0
	.ifc		\op, st
	.if		(\regcount) < 0 || (\regcount) > 10
	.error		"regcount should be in the range [0 ... 10]"
	.endif
	.if		((\extra) % 16) != 0
	.error		"extra should be a multiple of 16 bytes"
	.endif
	.ifdef		.Lframe_regcount
	.if		.Lframe_regcount != -1
	.error		"frame_push/frame_pop may not be nested"
	.endif
	.endif
	.set		.Lframe_regcount, \regcount
	.set		.Lframe_extra, \extra
	.set		.Lframe_local_offset, ((\regcount + 3) / 2) * 16
	stp		x29, x30, [sp, #-.Lframe_local_offset - .Lframe_extra]!
	mov		x29, sp
	.endif

	__frame_regs	x19, x20, \op, 1
	__frame_regs	x21, x22, \op, 3
	__frame_regs	x23, x24, \op, 5
	__frame_regs	x25, x26, \op, 7
	__frame_regs	x27, x28, \op, 9

	.ifc		\op, ld
	.if		.Lframe_regcount == -1
	.error		"frame_push/frame_pop may not be nested"
	.endif
	ldp		x29, x30, [sp], #.Lframe_local_offset + .Lframe_extra
	.set		.Lframe_regcount, -1
	.endif
	.endm

/*
 * Check whether to yield to another runnable task from kernel mode NEON code
 * (which runs with preemption disabled).
 *
 * if_will_cond_yield_neon
 *        // pre-yield patchup code
 * do_cond_yield_neon
 *        // post-yield patchup code
 * endif_yield_neon    <label>
 *
 * where <label> is optional, and marks the point where execution will resume
 * after a yield has been performed. If omitted, execution resumes right after
 * the endif_yield_neon invocation. Note that the entire sequence, including
 * the provided patchup code, will be omitted from the image if
 * CONFIG_PREEMPTION is not defined.
 *
 * As a convenience, in the case where no patchup code is required, the above
 * sequence may be abbreviated to
 *
 * cond_yield_neon <label>
 *
 * Note that the patchup code does not support assembler directives that change
 * the output section, any use of such directives is undefined.
 *
 * The yield itself consists of the following:
 * - Check whether the preempt count is exactly 1 and a reschedule is also
 *   needed. If so, calling of preempt_enable() in kernel_neon_end() will
 *   trigger a reschedule. If it is not the case, yielding is pointless.
 * - Disable and re-enable kernel mode NEON, and branch to the yield fixup
 *   code.
 *
 * This macro sequence may clobber all CPU state that is not guaranteed by the
 * AAPCS to be preserved across an ordinary function call.
 */

	.macro		cond_yield_neon, lbl
	if_will_cond_yield_neon
	do_cond_yield_neon
	endif_yield_neon	\lbl
	.endm

	.macro		if_will_cond_yield_neon
#ifdef CONFIG_PREEMPTION
	get_current_task	x0
	ldr		x0, [x0, #TSK_TI_PREEMPT]
	sub		x0, x0, #PREEMPT_DISABLE_OFFSET
	cbz		x0, .Lyield_\@
	/* fall through to endif_yield_neon */
	.subsection	1
.Lyield_\@ :
#else
	.section	".discard.cond_yield_neon", "ax"
#endif
	.endm

	.macro		do_cond_yield_neon
	bl		kernel_neon_end
	bl		kernel_neon_begin
	.endm

	.macro		endif_yield_neon, lbl
	.ifnb		\lbl
	b		\lbl
	.else
	b		.Lyield_out_\@
	.endif
	.previous
.Lyield_out_\@ :
	.endm

/*
 * This macro emits a program property note section identifying
 * architecture features which require special handling, mainly for
 * use in assembly files included in the VDSO.
 */

#define NT_GNU_PROPERTY_TYPE_0  5
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND      0xc0000000

#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI      (1U << 0)
#define GNU_PROPERTY_AARCH64_FEATURE_1_PAC      (1U << 1)

#ifdef CONFIG_ARM64_BTI_KERNEL
#define GNU_PROPERTY_AARCH64_FEATURE_1_DEFAULT		\
		((GNU_PROPERTY_AARCH64_FEATURE_1_BTI |	\
		  GNU_PROPERTY_AARCH64_FEATURE_1_PAC))
#endif

#ifdef GNU_PROPERTY_AARCH64_FEATURE_1_DEFAULT
.macro emit_aarch64_feature_1_and, feat=GNU_PROPERTY_AARCH64_FEATURE_1_DEFAULT
	.pushsection .note.gnu.property, "a"
	.align  3
	.long   2f - 1f
	.long   6f - 3f
	.long   NT_GNU_PROPERTY_TYPE_0
1:      .string "GNU"
2:
	.align  3
3:      .long   GNU_PROPERTY_AARCH64_FEATURE_1_AND
	.long   5f - 4f
4:
	/*
	 * This is described with an array of char in the Linux API
	 * spec but the text and all other usage (including binutils,
	 * clang and GCC) treat this as a 32 bit value so no swizzling
	 * is required for big endian.
	 */
	.long   \feat
5:
	.align  3
6:
	.popsection
.endm

#else
.macro emit_aarch64_feature_1_and, feat=0
.endm

#endif /* GNU_PROPERTY_AARCH64_FEATURE_1_DEFAULT */

#endif	/* __ASM_ASSEMBLER_H */
