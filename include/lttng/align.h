#ifndef _UST_ALIGN_H
#define _UST_ALIGN_H

/*
 * lttng/align.h
 *
 * (C) Copyright 2010-2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <lttng/bug.h>
#include <unistd.h>
#include <limits.h>

#ifdef __FreeBSD__
#include <machine/param.h>
#endif

#ifdef _SC_PAGE_SIZE
#define LTTNG_UST_PAGE_SIZE	sysconf(_SC_PAGE_SIZE)
#elif defined(PAGE_SIZE)
#define LTTNG_UST_PAGE_SIZE	PAGE_SIZE
#else
#error "Please add page size detection for your OS."
#endif

#define LTTNG_UST_PAGE_MASK	(~(LTTNG_UST_PAGE_SIZE - 1))

#define __LTTNG_UST_ALIGN_MASK(v, mask)	(((v) + (mask)) & ~(mask))
#define LTTNG_UST_ALIGN(v, align)	__LTTNG_UST_ALIGN_MASK(v, (__typeof__(v)) (align) - 1)
#define LTTNG_UST_PAGE_ALIGN(addr)	LTTNG_UST_ALIGN(addr, LTTNG_UST_PAGE_SIZE)

/**
 * lttng_ust_offset_align - Calculate the offset needed to align an object on
 *                its natural alignment towards higher addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be added to align towards higher
 * addresses.
 */
#define lttng_ust_offset_align(align_drift, alignment)			       \
	({								       \
		LTTNG_BUILD_RUNTIME_BUG_ON((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((alignment) - (align_drift)) & ((alignment) - 1));	       \
	})

/**
 * lttng_ust_offset_align_floor - Calculate the offset needed to align an
 *                object on its natural alignment towards lower addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be substracted to align towards lower addresses.
 */
#define lttng_ust_offset_align_floor(align_drift, alignment)		       \
	({								       \
		LTTNG_BUILD_RUNTIME_BUG_ON((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((align_drift) - (alignment)) & ((alignment) - 1));	       \
	})

/*
 * Non-namespaced defines for backwards compatibility,
 * introduced in 2.13, should be removed in the future.
 */

/* Cygwin limits.h defines its own PAGE_SIZE */
#ifndef PAGE_SIZE
#define PAGE_SIZE	LTTNG_UST_PAGE_SIZE
#endif

/* FreeBSD and macOS defines their own PAGE_MASK. */
#ifndef PAGE_MASK
#define PAGE_MASK	LTTNG_UST_PAGE_MASK
#endif

/* FreeBSD machine/param.h defines its own ALIGN */
#ifndef ALIGN
#define ALIGN		LTTNG_UST_ALIGN
#endif

#ifndef PAGE_ALIGN
#define PAGE_ALIGN	LTTNG_UST_PAGE_ALIGN
#endif

#ifndef offset_align
#define offset_align lttng_ust_offset_align
#endif

#ifndef offset_align_floor
#define offset_align_floor lttng_ust_offset_align_floor
#endif

#endif /* _UST_ALIGN_H */
