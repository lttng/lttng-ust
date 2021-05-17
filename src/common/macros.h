/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_MACROS_H
#define _UST_COMMON_MACROS_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <lttng/ust-arch.h>

/*
 * calloc() does not always populate the page table for the allocated
 * memory. Optionally enforce page table populate.
 */
static inline
void *zmalloc_populate(size_t len, bool populate)
	__attribute__((always_inline));
static inline
void *zmalloc_populate(size_t len, bool populate)
{
	if (populate) {
		void *ret = malloc(len);
		if (ret == NULL)
			return ret;
		bzero(ret, len);
		return ret;
	} else {
		return calloc(len, 1);
	}
}

/*
 * Memory allocation zeroed
 */
static inline
void *zmalloc(size_t len)
	__attribute__((always_inline));
static inline
void *zmalloc(size_t len)
{
	return zmalloc_populate(len, false);
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

#define lttng_ust_offsetofend(type, field)	\
	(offsetof(type, field) + sizeof(((type *)NULL)->field))

#endif /* _UST_COMMON_MACROS_H */
