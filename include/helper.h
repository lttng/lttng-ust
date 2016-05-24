#ifndef _LTTNG_UST_HELPER_H
#define _LTTNG_UST_HELPER_H

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdlib.h>

static inline __attribute__((always_inline))
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
#if defined(__PPC__) && !defined(__PPC64__)
#define LTTNG_UST_CALLER_IP()		NULL
#else /* #if defined(__PPC__) && !defined(__PPC64__) */
#define LTTNG_UST_CALLER_IP()		__builtin_return_address(0)
#endif /* #else #if defined(__PPC__) && !defined(__PPC64__) */

#endif /* _LTTNG_UST_HELPER_H */
