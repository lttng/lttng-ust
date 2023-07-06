// SPDX-FileCopyrightText: 2021 Michael Jeanson <mjeanson@efficios.com>
//
// SPDX-License-Identifier: MIT

#ifndef _LTTNG_UST_ARCH_H
#define _LTTNG_UST_ARCH_H

/*
 * Architecture detection using compiler defines.
 *
 * The following defines are used internally for architecture specific code.
 *
 * LTTNG_UST_ARCH_X86 : All x86 variants 32 and 64 bits
 *   LTTNG_UST_ARCH_I386 : Specific to the i386
 *   LTTNG_UST_ARCH_AMD64 : All 64 bits x86 variants
 *   LTTNG_UST_ARCH_K1OM : Specific to the Xeon Phi / MIC
 *
 * LTTNG_UST_ARCH_PPC : All PowerPC variants 32 and 64 bits
 *   LTTNG_UST_ARCH_PPC64 : Specific to 64 bits variants
 *
 * LTTNG_UST_ARCH_S390 : All IBM s390 / s390x variants
 *
 * LTTNG_UST_ARCH_SPARC64 : All Sun SPARC variants
 *
 * LTTNG_UST_ARCH_ALPHA : All DEC Alpha variants
 * LTTNG_UST_ARCH_IA64 : All Intel Itanium variants
 * LTTNG_UST_ARCH_ARM : All ARM 32 bits variants
 *   LTTNG_UST_ARCH_ARMV7 : All ARMv7 ISA variants
 * LTTNG_UST_ARCH_AARCH64 : All ARM 64 bits variants
 * LTTNG_UST_ARCH_MIPS : All MIPS variants
 * LTTNG_UST_ARCH_NIOS2 : All Intel / Altera NIOS II variants
 * LTTNG_UST_ARCH_TILE : All Tilera TILE variants
 * LTTNG_UST_ARCH_HPPA : All HP PA-RISC variants
 * LTTNG_UST_ARCH_M68K : All Motorola 68000 variants
 * LTTNG_UST_ARCH_RISCV : All RISC-V variants
 */

#if (defined(__INTEL_OFFLOAD) || defined(__TARGET_ARCH_MIC) || defined(__MIC__))

#define LTTNG_UST_ARCH_X86 1
#define LTTNG_UST_ARCH_AMD64 1
#define LTTNG_UST_ARCH_K1OM 1

#elif (defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64))

#define LTTNG_UST_ARCH_X86 1
#define LTTNG_UST_ARCH_AMD64 1

#elif (defined(__i486__) || defined(__i586__) || defined(__i686__))

#define LTTNG_UST_ARCH_X86 1

#elif (defined(__i386__) || defined(__i386))

#define LTTNG_UST_ARCH_X86 1
#define LTTNG_UST_ARCH_I386 1

#elif (defined(__powerpc64__) || defined(__ppc64__))

#define LTTNG_UST_ARCH_PPC 1
#define LTTNG_UST_ARCH_PPC64 1

#elif (defined(__powerpc__) || defined(__powerpc) || defined(__ppc__))

#define LTTNG_UST_ARCH_PPC 1

#elif (defined(__s390__) || defined(__s390x__) || defined(__zarch__))

#define LTTNG_UST_ARCH_S390 1

#elif (defined(__sparc__) || defined(__sparc) || defined(__sparc64__))

#define LTTNG_UST_ARCH_SPARC64 1

#elif (defined(__alpha__) || defined(__alpha))

#define LTTNG_UST_ARCH_ALPHA 1

#elif (defined(__ia64__) || defined(__ia64))

#define LTTNG_UST_ARCH_IA64 1

#elif (defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7__))

#define LTTNG_UST_ARCH_ARMV7 1
#define LTTNG_UST_ARCH_ARM 1

#elif (defined(__arm__) || defined(__arm))

#define LTTNG_UST_ARCH_ARM 1

#elif defined(__aarch64__)

#define LTTNG_UST_ARCH_AARCH64 1

#elif (defined(__mips__) || defined(__mips))

#define LTTNG_UST_ARCH_MIPS 1

#elif (defined(__nios2__) || defined(__nios2))

#define LTTNG_UST_ARCH_NIOS2 1

#elif (defined(__tile__) || defined(__tilegx__))

#define LTTNG_UST_ARCH_TILE 1

#elif (defined(__hppa__) || defined(__HPPA__) || defined(__hppa))

#define LTTNG_UST_ARCH_HPPA 1

#elif defined(__m68k__)

#define LTTNG_UST_ARCH_M68K 1

#elif defined(__riscv)

#define LTTNG_UST_ARCH_RISCV 1

#else

/* Unrecognised architecture, use safe defaults */
#define LTTNG_UST_ARCH_UNKNOWN 1

#endif


/*
 * Per architecture global settings.
 *
 * LTTNG_UST_ARCH_HAS_EFFICIENT_UNALIGNED_ACCESS:
 *   The architecture has working and efficient unaligned memory access, the
 *   content of the ringbuffers will packed instead of following the natural
 *   alignment of the architecture.
 */

#if defined(LTTNG_UST_ARCH_X86)
#define LTTNG_UST_ARCH_HAS_EFFICIENT_UNALIGNED_ACCESS 1
#endif

#if defined(LTTNG_UST_ARCH_PPC)
#define LTTNG_UST_ARCH_HAS_EFFICIENT_UNALIGNED_ACCESS 1
#endif

#endif /* _LTTNG_UST_ARCH_H */
