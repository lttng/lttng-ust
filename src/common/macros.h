/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_MACROS_H
#define _UST_COMMON_MACROS_H

#include <stdlib.h>

#include <lttng/ust-arch.h>

/*
 * Memory allocation zeroed
 */
static inline
void *zmalloc(size_t len)
	__attribute__((always_inline));
static inline
void *zmalloc(size_t len)
{
	return calloc(len, 1);
}

#define max_t(type, x, y)				\
	({						\
		type __max1 = (x);              	\
		type __max2 = (y);              	\
		__max1 > __max2 ? __max1: __max2;	\
	})

#define min_t(type, x, y)				\
	({						\
		type __min1 = (x);              	\
		type __min2 = (y);              	\
		__min1 <= __min2 ? __min1: __min2;	\
	})

#define LTTNG_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * Use of __builtin_return_address(0) sometimes seems to cause stack
 * corruption on 32-bit PowerPC. Disable this feature on that
 * architecture for now by always using the NULL value for the ip
 * context.
 */
#if defined(LTTNG_UST_ARCH_PPC) && !defined(LTTNG_UST_ARCH_PPC64)
#define LTTNG_UST_CALLER_IP()		NULL
#else
#define LTTNG_UST_CALLER_IP()		__builtin_return_address(0)
#endif

#endif /* _UST_COMMON_MACROS_H */
