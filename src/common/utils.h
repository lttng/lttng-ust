/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#ifndef _UST_COMMON_UTILS_H
#define _UST_COMMON_UTILS_H

#include <stdint.h>
#include <lttng/ust-arch.h>
#include <urcu/compiler.h>

ssize_t lttng_ust_read(int fd, void *buf, size_t len)
	__attribute__((visibility("hidden")));

/*
 * fls: returns the position of the most significant bit.
 * Returns 0 if no bit is set, else returns the position of the most
 * significant bit (from 1 to 32 on 32-bit, from 1 to 64 on 64-bit).
 */
#if defined(LTTNG_UST_ARCH_X86)
static inline
unsigned int lttng_ust_fls_u32(uint32_t x)
{
	int r;

	__asm__ ("bsrl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U32
#endif

#if defined(LTTNG_UST_ARCH_AMD64)
static inline
unsigned int lttng_ust_fls_u64(uint64_t x)
{
	long r;

	__asm__ ("bsrq %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movq $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U64
#endif

#ifndef HAS_FLS_U32
static inline
unsigned int lttng_ust_fls_u32(uint32_t x)
{
	unsigned int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		/* No need to bit shift on last operation */
		r -= 1;
	}
	return r;
}
#endif

#ifndef HAS_FLS_U64
static inline
unsigned int lttng_ust_fls_u64(uint64_t x)
{
	unsigned int r = 64;

	if (!x)
		return 0;
	if (!(x & 0xFFFFFFFF00000000ULL)) {
		x <<= 32;
		r -= 32;
	}
	if (!(x & 0xFFFF000000000000ULL)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF00000000000000ULL)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF000000000000000ULL)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC000000000000000ULL)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x8000000000000000ULL)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

static inline
unsigned int lttng_ust_fls_ulong(unsigned long x)
{
#if (CAA_BITS_PER_LONG == 32)
	return lttng_ust_fls_u32(x);
#else
	return lttng_ust_fls_u64(x);
#endif
}

static inline int lttng_ust_get_count_order_u32(uint32_t count)
{
	int order;

	order = lttng_ust_fls_u32(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

static inline int lttng_ust_get_count_order_u64(uint64_t count)
{
	int order;

	order = lttng_ust_fls_u64(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

static inline int lttng_ust_get_count_order_ulong(unsigned long count)
{
#if (CAA_BITS_PER_LONG == 32)
	return lttng_ust_get_count_order_u32(count);
#else
	return lttng_ust_get_count_order_u64(count);
#endif
}

#endif
